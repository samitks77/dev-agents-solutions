[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Subscription,
    [Parameter(Mandatory)][string]$ExpectedTenantId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$Location,
    [Parameter(Mandatory)][string]$VirtualNetworkAddressPrefix,
    [Parameter(Mandatory)][string]$RunnerSubnetAddressPrefix,
    [Parameter(Mandatory)][string]$PrivateEndpointSubnetAddressPrefix,
    [switch]$ConfirmManagedIdentityServicePrincipals,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$templateFile = Join-Path $labRoot 'infra\main.bicep'
. (Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1')
. (Join-Path $PSScriptRoot 'Runner-Network.ps1')

Assert-LabNetworkPrefixes `
    -VirtualNetworkAddressPrefix $VirtualNetworkAddressPrefix `
    -RunnerSubnetAddressPrefix $RunnerSubnetAddressPrefix `
    -PrivateEndpointSubnetAddressPrefix $PrivateEndpointSubnetAddressPrefix

if (-not $WhatIf -and -not $ConfirmManagedIdentityServicePrincipals) {
    throw (
        'Infrastructure deployment creates two user-assigned managed identities and Azure ' +
        'automatically creates their backing Microsoft Entra service principals. Rerun with ' +
        '-ConfirmManagedIdentityServicePrincipals to acknowledge this directory side effect.'
    )
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required.'
}

az account set --subscription $Subscription
$account = az account show -o json | ConvertFrom-Json
if ($account.tenantId -ne $ExpectedTenantId) {
    throw "Subscription '$Subscription' belongs to tenant '$($account.tenantId)', not '$ExpectedTenantId'."
}

$groupExists = az group exists --name $ResourceGroup
if ($groupExists -ne 'true') {
    if ($WhatIf) {
        throw "Resource group '$ResourceGroup' does not exist; refusing to create it during a what-if operation."
    }
    $expiresOn = [DateTime]::UtcNow.AddDays(7).ToString('yyyy-MM-dd')
    az group create `
        --name $ResourceGroup `
        --location $Location `
        --tags environment=poc workload=entra-cba-playwright managedBy=bicep "expiresOn=$expiresOn" `
        --output none
}

New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null

$deploymentName = "entra-cba-poc-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"
if ($WhatIf) {
    az deployment group what-if `
        --name $deploymentName `
        --resource-group $ResourceGroup `
        --template-file $templateFile `
        --parameters `
            location=$Location `
            confirmManagedIdentityServicePrincipals=$true `
            virtualNetworkAddressPrefix=$VirtualNetworkAddressPrefix `
            runnerSubnetAddressPrefix=$RunnerSubnetAddressPrefix `
            privateEndpointSubnetAddressPrefix=$PrivateEndpointSubnetAddressPrefix
    if ($LASTEXITCODE -ne 0) {
        throw "Infrastructure what-if failed with exit code $LASTEXITCODE."
    }
    $existingStatePath = Join-Path $stateDirectory 'infrastructure.json'
    if (Test-Path -LiteralPath $existingStatePath) {
        $existingState = Get-Content -LiteralPath $existingStatePath -Raw | ConvertFrom-Json
        Assert-LabVaultRbac -Outputs $existingState.outputs -ResourceGroup $ResourceGroup
    }
    Write-Host "Infrastructure what-if succeeded in '$ResourceGroup'."
    return
}

az deployment group create `
    --name $deploymentName `
    --resource-group $ResourceGroup `
    --template-file $templateFile `
    --parameters `
        location=$Location `
        confirmManagedIdentityServicePrincipals=$true `
        virtualNetworkAddressPrefix=$VirtualNetworkAddressPrefix `
        runnerSubnetAddressPrefix=$RunnerSubnetAddressPrefix `
        privateEndpointSubnetAddressPrefix=$PrivateEndpointSubnetAddressPrefix `
    --output none

$outputs = az deployment group show `
    --name $deploymentName `
    --resource-group $ResourceGroup `
    --query properties.outputs `
    --output json | ConvertFrom-Json

Assert-LabVaultRbac -Outputs $outputs -ResourceGroup $ResourceGroup

$state = [ordered]@{
    deploymentName = $deploymentName
    subscriptionId = $account.id
    subscriptionName = $account.name
    tenantId = $account.tenantId
    resourceGroup = $ResourceGroup
    location = $Location
    outputs = $outputs
}

$statePath = Join-Path $stateDirectory 'infrastructure.json'
$state | ConvertTo-Json -Depth 10 | Set-Content -Path $statePath -Encoding utf8NoBOM

Write-Host "Infrastructure deployment succeeded in '$ResourceGroup'."
Write-Host "State: $statePath"
Write-Host "Application URL: $($outputs.appUrl.value)"
Write-Host "CRL URL: $($outputs.crlUrl.value)"
