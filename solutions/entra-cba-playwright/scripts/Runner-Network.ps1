function ConvertTo-Ipv4Number {
    param([Parameter(Mandatory)][string]$Address)

    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsedAddress) -or
        $parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $parsedAddress.ToString() -cne $Address) {
        throw "IPv4 address '$Address' is invalid or non-canonical."
    }

    $bytes = $parsedAddress.GetAddressBytes()
    return (
        ([uint64]$bytes[0] -shl 24) -bor
        ([uint64]$bytes[1] -shl 16) -bor
        ([uint64]$bytes[2] -shl 8) -bor
        [uint64]$bytes[3]
    )
}

function Get-Ipv4CidrRange {
    param([Parameter(Mandatory)][string]$Cidr)

    $cidrParts = $Cidr.Split('/')
    $prefixLength = 0
    if ($cidrParts.Count -ne 2 -or
        -not [int]::TryParse($cidrParts[1], [ref]$prefixLength) -or
        $prefixLength.ToString() -cne $cidrParts[1] -or
        $prefixLength -lt 0 -or
        $prefixLength -gt 32) {
        throw "CIDR '$Cidr' is invalid."
    }

    $addressNumber = ConvertTo-Ipv4Number -Address $cidrParts[0]
    $hostBits = 32 - $prefixLength
    $hostMask = if ($hostBits -eq 32) {
        [uint64]4294967295
    } else {
        ([uint64]1 -shl $hostBits) - 1
    }
    $networkMask = [uint64]4294967295 -bxor $hostMask
    $networkNumber = $addressNumber -band $networkMask
    if ($addressNumber -ne $networkNumber) {
        throw "CIDR '$Cidr' must start at its canonical network address."
    }

    return [pscustomobject]@{
        Cidr = $Cidr
        Network = $networkNumber
        LastAddress = $networkNumber + $hostMask
        PrefixLength = $prefixLength
    }
}

function Get-Rfc1918Block {
    param([Parameter(Mandatory)][uint64]$AddressNumber)

    $firstOctet = [int](($AddressNumber -shr 24) -band 255)
    $secondOctet = [int](($AddressNumber -shr 16) -band 255)
    if ($firstOctet -eq 10) {
        return 'class-a-private'
    }
    if ($firstOctet -eq 172 -and $secondOctet -ge 16 -and $secondOctet -le 31) {
        return 'class-b-private'
    }
    if ($firstOctet -eq 192 -and $secondOctet -eq 168) {
        return 'class-c-private'
    }
    return $null
}

function Assert-LabNetworkPrefixes {
    param(
        [Parameter(Mandatory)][string]$VirtualNetworkAddressPrefix,
        [Parameter(Mandatory)][string]$RunnerSubnetAddressPrefix,
        [Parameter(Mandatory)][string]$PrivateEndpointSubnetAddressPrefix
    )

    $virtualNetwork = Get-Ipv4CidrRange -Cidr $VirtualNetworkAddressPrefix
    $runnerSubnet = Get-Ipv4CidrRange -Cidr $RunnerSubnetAddressPrefix
    $privateEndpointSubnet = Get-Ipv4CidrRange -Cidr $PrivateEndpointSubnetAddressPrefix
    $ranges = [ordered]@{
        'Virtual network' = $virtualNetwork
        'Runner subnet' = $runnerSubnet
        'Private endpoint subnet' = $privateEndpointSubnet
    }

    foreach ($entry in $ranges.GetEnumerator()) {
        $firstBlock = Get-Rfc1918Block -AddressNumber $entry.Value.Network
        $lastBlock = Get-Rfc1918Block -AddressNumber $entry.Value.LastAddress
        if (-not $firstBlock -or $firstBlock -ne $lastBlock) {
            throw "$($entry.Key) CIDR '$($entry.Value.Cidr)' must be entirely within one RFC 1918 range."
        }
        if ($entry.Value.PrefixLength -gt 29) {
            throw "$($entry.Key) CIDR '$($entry.Value.Cidr)' must contain at least eight addresses."
        }
    }

    foreach ($subnet in @($runnerSubnet, $privateEndpointSubnet)) {
        if ($subnet.Network -lt $virtualNetwork.Network -or
            $subnet.LastAddress -gt $virtualNetwork.LastAddress -or
            $subnet.PrefixLength -le $virtualNetwork.PrefixLength) {
            throw "Subnet CIDR '$($subnet.Cidr)' must be contained by and smaller than '$($virtualNetwork.Cidr)'."
        }
    }

    if ($runnerSubnet.Network -le $privateEndpointSubnet.LastAddress -and
        $privateEndpointSubnet.Network -le $runnerSubnet.LastAddress) {
        throw "Runner and private endpoint subnet CIDRs must not overlap."
    }
}

function Test-Ipv4AddressInCidr {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Cidr
    )

    $range = Get-Ipv4CidrRange -Cidr $Cidr
    $addressNumber = ConvertTo-Ipv4Number -Address $Address
    return (
        $addressNumber -ge $range.Network -and
        $addressNumber -le $range.LastAddress
    )
}

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
    $runnerNatGatewayId = if (
        $runnerSubnet.PSObject.Properties.Name -contains 'natGateway' -and
        $runnerSubnet.natGateway
    ) {
        [string]$runnerSubnet.natGateway.id
    }
    else {
        $null
    }
    $runnerRouteTableId = if (
        $runnerSubnet.PSObject.Properties.Name -contains 'routeTable' -and
        $runnerSubnet.routeTable
    ) {
        [string]$runnerSubnet.routeTable.id
    }
    else {
        $null
    }
    if ($runnerSubnetPrefixes.Count -ne 1 -or
        @($runnerSubnet.delegations.serviceName).Count -ne 1 -or
        $runnerSubnet.delegations[0].serviceName -ne 'Microsoft.ContainerInstance/containerGroups' -or
        -not $runnerNatGatewayId -or
        $runnerRouteTableId) {
        throw 'The runner subnet does not have one prefix, the ACI delegation, direct NAT egress, and no UDR.'
    }

    $natGateway = az network nat gateway show `
        --ids $runnerNatGatewayId `
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
