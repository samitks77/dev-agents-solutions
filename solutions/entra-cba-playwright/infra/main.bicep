targetScope = 'resourceGroup'

@description('Azure region for all regional resources.')
param location string = resourceGroup().location

@description('Tags applied to every resource that supports tags.')
param tags object = {
  environment: 'poc'
  workload: 'entra-cba-playwright'
  managedBy: 'bicep'
}

var suffix = uniqueString(subscription().subscriptionId, resourceGroup().id)
var logAnalyticsName = 'log-entra-cba-pw-${suffix}'
var keyVaultPrivateEndpointName = 'pep-${runnerVaultName}'
var keyVaultPrivateDnsZoneName = 'privatelink.vaultcore.azure.net'
var runnerNatGatewayName = 'nat-entra-cba-pw-${suffix}'
var runnerOutboundIpName = 'pip-entra-cba-pw-${suffix}'
var runnerSubnetName = 'snet-github-runner'
var runnerVaultName = 'kv-cba-run-${suffix}'
var privateEndpointSubnetName = 'snet-private-endpoints'
var publisherIdentityName = 'id-entra-cba-publisher-poc'
var staticWebAppName = 'stapp-entra-cba-pw-${suffix}'
var virtualNetworkName = 'vnet-entra-cba-pw-${suffix}'
var workloadIdentityName = 'id-entra-cba-github-poc'

var keyVaultSecretsUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    sku: {
      name: 'PerGB2018'
    }
  }
}

resource workloadIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: workloadIdentityName
  location: location
  tags: tags
}

resource publisherIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: publisherIdentityName
  location: location
  tags: tags
}

resource runnerOutboundIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: runnerOutboundIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource runnerNatGateway 'Microsoft.Network/natGateways@2023-11-01' = {
  name: runnerNatGatewayName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [
      {
        id: runnerOutboundIp.id
      }
    ]
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: virtualNetworkName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.42.0.0/16'
      ]
    }
  }
}

resource runnerSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' = {
  parent: virtualNetwork
  name: runnerSubnetName
  properties: {
    addressPrefix: '10.42.1.0/24'
    delegations: [
      {
        name: 'container-instances'
        properties: {
          serviceName: 'Microsoft.ContainerInstance/containerGroups'
        }
      }
    ]
    natGateway: {
      id: runnerNatGateway.id
    }
  }
}

resource privateEndpointSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' = {
  parent: virtualNetwork
  name: privateEndpointSubnetName
  properties: {
    addressPrefix: '10.42.2.0/24'
    privateEndpointNetworkPolicies: 'Disabled'
  }
}

resource runnerVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: runnerVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
    }
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

resource keyVaultPrivateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: keyVaultPrivateDnsZoneName
  location: 'global'
  tags: tags
}

resource keyVaultPrivateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: keyVaultPrivateDnsZone
  name: 'link-${virtualNetworkName}'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetwork.id
    }
  }
}

resource keyVaultPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: keyVaultPrivateEndpointName
  location: location
  tags: tags
  properties: {
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          groupIds: [
            'vault'
          ]
          privateLinkServiceId: runnerVault.id
          requestMessage: 'Private access for the ephemeral GitHub Actions runner.'
        }
      }
    ]
    subnet: {
      id: privateEndpointSubnet.id
    }
  }
}

resource keyVaultPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: keyVaultPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: keyVaultPrivateDnsZone.id
        }
      }
    ]
  }
}

resource runnerVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-audit-to-log-analytics'
  scope: runnerVault
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

resource runnerVaultReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(runnerVault.id, workloadIdentity.id, keyVaultSecretsUserRoleId)
  scope: runnerVault
  properties: {
    principalId: workloadIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

resource staticWebApp 'Microsoft.Web/staticSites@2023-12-01' = {
  name: staticWebAppName
  location: location
  tags: tags
  sku: {
    name: 'Free'
    tier: 'Free'
  }
  properties: {
    allowConfigFileUpdates: true
    enterpriseGradeCdnStatus: 'Disabled'
    publicNetworkAccess: 'Enabled'
    stagingEnvironmentPolicy: 'Disabled'
  }
}

output appUrl string = 'https://${staticWebApp.properties.defaultHostname}/'
output crlUrl string = 'http://${staticWebApp.properties.defaultHostname}/crl/entra-cba-lab.crl'
output logAnalyticsWorkspaceName string = logAnalytics.name
output keyVaultPrivateEndpointName string = keyVaultPrivateEndpoint.name
output publisherClientId string = publisherIdentity.properties.clientId
output publisherIdentityName string = publisherIdentity.name
output publisherPrincipalId string = publisherIdentity.properties.principalId
output publisherResourceId string = publisherIdentity.id
output runnerOutboundIpAddress string = runnerOutboundIp.properties.ipAddress
output runnerSubnetId string = runnerSubnet.id
output runnerVaultName string = runnerVault.name
output staticWebAppName string = staticWebApp.name
output workloadClientId string = workloadIdentity.properties.clientId
output workloadIdentityName string = workloadIdentity.name
output workloadPrincipalId string = workloadIdentity.properties.principalId
output workloadResourceId string = workloadIdentity.id
output virtualNetworkName string = virtualNetwork.name
