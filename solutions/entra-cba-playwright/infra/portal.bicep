targetScope = 'resourceGroup'

@description('Azure region for all regional resources.')
param location string = resourceGroup().location

@description('Tags applied to every resource that supports tags.')
param tags object = {
  environment: 'poc'
  workload: 'entra-cba-playwright'
  managedBy: 'bicep'
}

@description('Select a predefined RFC1918 topology that does not overlap with networks you may connect to this lab.')
@allowed([
  '10-range'
  '172-range'
  '192-range'
])
param networkProfile string = '10-range'

@description('Required acknowledgement: deploying the two managed identities causes Azure to create their backing Microsoft Entra service principals. No Conditional Access or other Entra configuration is performed.')
@allowed([
  true
])
param confirmManagedIdentityServicePrincipals bool

var virtualNetworkAddressPrefix = networkProfile == '10-range'
  ? '10.42.0.0/24'
  : networkProfile == '172-range'
    ? '172.20.42.0/24'
    : '192.168.42.0/24'
var runnerSubnetAddressPrefix = networkProfile == '10-range'
  ? '10.42.0.0/26'
  : networkProfile == '172-range'
    ? '172.20.42.0/26'
    : '192.168.42.0/26'
var privateEndpointSubnetAddressPrefix = networkProfile == '10-range'
  ? '10.42.0.64/26'
  : networkProfile == '172-range'
    ? '172.20.42.64/26'
    : '192.168.42.64/26'

module infrastructure 'main.bicep' = {
  name: 'entra-cba-playwright-infrastructure'
  params: {
    location: location
    tags: tags
    confirmManagedIdentityServicePrincipals: confirmManagedIdentityServicePrincipals
    virtualNetworkAddressPrefix: virtualNetworkAddressPrefix
    runnerSubnetAddressPrefix: runnerSubnetAddressPrefix
    privateEndpointSubnetAddressPrefix: privateEndpointSubnetAddressPrefix
  }
}

output appUrl string = infrastructure.outputs.appUrl
output crlUrl string = infrastructure.outputs.crlUrl
output logAnalyticsWorkspaceName string = infrastructure.outputs.logAnalyticsWorkspaceName
output keyVaultPrivateEndpointName string = infrastructure.outputs.keyVaultPrivateEndpointName
output publisherClientId string = infrastructure.outputs.publisherClientId
output publisherIdentityName string = infrastructure.outputs.publisherIdentityName
output publisherPrincipalId string = infrastructure.outputs.publisherPrincipalId
output publisherResourceId string = infrastructure.outputs.publisherResourceId
output runnerOutboundIpAddress string = infrastructure.outputs.runnerOutboundIpAddress
output runnerSubnetId string = infrastructure.outputs.runnerSubnetId
output runnerVaultName string = infrastructure.outputs.runnerVaultName
output staticWebAppName string = infrastructure.outputs.staticWebAppName
output workloadClientId string = infrastructure.outputs.workloadClientId
output workloadIdentityName string = infrastructure.outputs.workloadIdentityName
output workloadPrincipalId string = infrastructure.outputs.workloadPrincipalId
output workloadResourceId string = infrastructure.outputs.workloadResourceId
output virtualNetworkName string = infrastructure.outputs.virtualNetworkName
