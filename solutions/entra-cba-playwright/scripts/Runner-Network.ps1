function Get-RunnerNetworkContract {
    param([Parameter(Mandatory)][object]$Infrastructure)

    $resourceGroup = [string]$Infrastructure.resourceGroup
    $runnerSubnetId = [string]$Infrastructure.outputs.runnerSubnetId.value
    $vaultName = [string]$Infrastructure.outputs.runnerVaultName.value
    $privateEndpointName = [string]$Infrastructure.outputs.keyVaultPrivateEndpointName.value
    $virtualNetworkName = [string]$Infrastructure.outputs.virtualNetworkName.value
    foreach ($requiredValue in @(
        $resourceGroup,
        $runnerSubnetId,
        $vaultName,
        $privateEndpointName,
        $virtualNetworkName
    )) {
        if (-not $requiredValue) {
            throw 'Infrastructure state does not contain the complete runner network identity.'
        }
    }

    $vault = az keyvault show `
        --name $vaultName `
        --resource-group $resourceGroup `
        --output json | ConvertFrom-Json
    if ($vault.properties.publicNetworkAccess -ne 'Disabled' -or
        $vault.properties.networkAcls.defaultAction -ne 'Deny') {
        throw "Key Vault '$vaultName' is not private-only and deny-by-default."
    }

    $runnerSubnet = az network vnet subnet show `
        --ids $runnerSubnetId `
        --output json | ConvertFrom-Json
    $runnerSubnetPrefixes = @(
        @($runnerSubnet.addressPrefix) + @($runnerSubnet.addressPrefixes) |
            Where-Object { $_ }
    )
    if ($runnerSubnetPrefixes.Count -ne 1 -or
        @($runnerSubnet.delegations.serviceName).Count -ne 1 -or
        $runnerSubnet.delegations[0].serviceName -ne 'Microsoft.ContainerInstance/containerGroups' -or
        -not $runnerSubnet.natGateway.id -or
        $runnerSubnet.routeTable.id) {
        throw 'The runner subnet does not have one prefix, the ACI delegation, direct NAT egress, and no UDR.'
    }

    $natGateway = az network nat gateway show `
        --ids $runnerSubnet.natGateway.id `
        --output json | ConvertFrom-Json
    if (@($natGateway.publicIpAddresses).Count -ne 1 -or
        @($natGateway.publicIpPrefixes | Where-Object { $_ }).Count -ne 0) {
        throw 'The runner NAT gateway must use exactly one public IP and no public IP prefixes.'
    }
    $outboundIp = az network public-ip show `
        --ids $natGateway.publicIpAddresses[0].id `
        --query ipAddress `
        --output tsv
    if (-not $outboundIp -or
        $outboundIp -ne $Infrastructure.outputs.runnerOutboundIpAddress.value) {
        throw 'The runner NAT public IP does not match infrastructure state.'
    }

    $privateEndpoint = az network private-endpoint show `
        --name $privateEndpointName `
        --resource-group $resourceGroup `
        --output json | ConvertFrom-Json
    $connections = @($privateEndpoint.privateLinkServiceConnections)
    if ($connections.Count -ne 1 -or
        $connections[0].privateLinkServiceId -ne $vault.id -or
        @($connections[0].groupIds).Count -ne 1 -or
        $connections[0].groupIds[0] -ne 'vault' -or
        $connections[0].privateLinkServiceConnectionState.status -ne 'Approved' -or
        @($privateEndpoint.networkInterfaces).Count -ne 1) {
        throw 'The Key Vault private endpoint connection is not exact and approved.'
    }

    $privateEndpointNic = az network nic show `
        --ids $privateEndpoint.networkInterfaces[0].id `
        --output json | ConvertFrom-Json
    $privateEndpointIpConfigurations = @($privateEndpointNic.ipConfigurations)
    if ($privateEndpointIpConfigurations.Count -ne 1 -or
        -not $privateEndpointIpConfigurations[0].privateIPAddress) {
        throw 'The Key Vault private endpoint does not have one private IPv4 address.'
    }
    $privateEndpointIp = [string]$privateEndpointIpConfigurations[0].privateIPAddress

    $privateDnsZoneName = 'privatelink.vaultcore.azure.net'
    $vaultDnsRecord = az network private-dns record-set a show `
        --resource-group $resourceGroup `
        --zone-name $privateDnsZoneName `
        --name $vaultName `
        --output json | ConvertFrom-Json
    $dnsAddresses = @($vaultDnsRecord.aRecords.ipv4Address)
    if ($dnsAddresses.Count -ne 1 -or $dnsAddresses[0] -ne $privateEndpointIp) {
        throw 'The Key Vault private DNS A record does not match the private endpoint IP.'
    }

    $virtualNetwork = az network vnet show `
        --name $virtualNetworkName `
        --resource-group $resourceGroup `
        --output json | ConvertFrom-Json
    $dnsLinks = @(
        az network private-dns link vnet list `
            --resource-group $resourceGroup `
            --zone-name $privateDnsZoneName `
            --output json | ConvertFrom-Json
    )
    $matchingDnsLinks = @($dnsLinks | Where-Object {
        $_.virtualNetwork.id -eq $virtualNetwork.id -and
        $_.registrationEnabled -eq $false -and
        $_.virtualNetworkLinkState -eq 'Completed'
    })
    if ($matchingDnsLinks.Count -ne 1) {
        throw 'The Key Vault private DNS zone is not linked exactly once to the runner VNet.'
    }

    return [pscustomobject]@{
        keyVaultId = $vault.id
        keyVaultName = $vaultName
        privateDnsZone = $privateDnsZoneName
        privateEndpointId = $privateEndpoint.id
        privateEndpointIp = $privateEndpointIp
        privateEndpointSubnetId = $privateEndpoint.subnet.id
        runnerNatGatewayId = $natGateway.id
        runnerOutboundIp = $outboundIp
        runnerSubnetCidr = $runnerSubnetPrefixes[0]
        runnerSubnetId = $runnerSubnet.id
        virtualNetworkId = $virtualNetwork.id
    }
}
