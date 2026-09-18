[CmdletBinding(DefaultParameterSetName = 'Object')]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup,

    [string]$DeploymentName,

    [Parameter(ParameterSetName = 'File')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$DeploymentOutputsPath,

    [Parameter(ParameterSetName = 'Object')]
    [object]$DeploymentOutputsObject,

    [ValidateNotNullOrEmpty()]
    [string]$StatePath = (
        Join-Path (Split-Path -Parent $PSScriptRoot) '.lab-state\infrastructure.json'
    )
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'Runner-Network.ps1')
. (Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1')

function Write-InfrastructureStateAtomically {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Collections.IDictionary]$State
    )

    $writeId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$Path.$writeId.tmp"
    $backupPath = "$Path.$writeId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($State | ConvertTo-Json -Depth 10),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
        }
        else {
            [IO.File]::Move($temporaryPath, $Path)
        }
    }
    finally {
        foreach ($cleanupPath in @($temporaryPath, $backupPath)) {
            if (Test-Path -LiteralPath $cleanupPath) {
                Remove-Item -LiteralPath $cleanupPath -Force
            }
        }
    }
}

function Get-DeploymentOutputValue {
    param(
        [Parameter(Mandatory)]
        [object]$Outputs,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $property = $Outputs.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "Deployment outputs do not contain '$Name'."
    }

    $valueProperty = $property.Value.PSObject.Properties['value']
    $value = if ($null -ne $valueProperty) {
        $valueProperty.Value
    }
    else {
        $property.Value
    }
    if ([string]::IsNullOrWhiteSpace([string]$value)) {
        throw "Deployment output '$Name' is empty."
    }

    return $value
}

function Assert-ExactValue {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Expected,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Actual,

        [switch]$CaseSensitive
    )

    $comparison = if ($CaseSensitive) {
        [StringComparison]::Ordinal
    }
    else {
        [StringComparison]::OrdinalIgnoreCase
    }
    if (-not [string]::Equals($Expected, $Actual, $comparison)) {
        throw "$Name does not match the live Azure resource."
    }
}

$stateDirectory = Split-Path -Parent $StatePath
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$importLockPath = Join-Path $stateDirectory 'infrastructure-import.lock'
try {
    $importLock = [IO.File]::Open(
        $importLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another infrastructure import owns the exclusive local binding lock.'
}
try {
az account set --subscription $SubscriptionId | Out-Null
$account = az account show --output json | ConvertFrom-Json
Assert-ExactValue `
    -Name 'Requested tenant' `
    -Expected $TenantId `
    -Actual ([string]$account.tenantId)

$resolvedSubscriptionId = [string]$account.id
$resourceGroupObject = az group show `
    --name $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
$expectedResourceGroupId = "/subscriptions/$resolvedSubscriptionId/resourceGroups/$ResourceGroup"
Assert-ExactValue `
    -Name 'Resource group identity' `
    -Expected $expectedResourceGroupId `
    -Actual ([string]$resourceGroupObject.id)

$sourceDeployment = 'provided-object'
if ($DeploymentOutputsPath) {
    $raw = Get-Content -LiteralPath $DeploymentOutputsPath -Raw | ConvertFrom-Json
    if ($raw.PSObject.Properties['properties'] -and $raw.properties.PSObject.Properties['outputs']) {
        $DeploymentOutputsObject = $raw.properties.outputs
    }
    elseif ($raw.PSObject.Properties['outputs']) {
        $DeploymentOutputsObject = $raw.outputs
    }
    else {
        $DeploymentOutputsObject = $raw
    }
    $sourceDeployment = (Resolve-Path -LiteralPath $DeploymentOutputsPath).Path
}
elseif ($null -eq $DeploymentOutputsObject) {
    if ($DeploymentName) {
        $deployment = az deployment group show `
            --name $DeploymentName `
            --resource-group $ResourceGroup `
            --subscription $resolvedSubscriptionId `
            --output json | ConvertFrom-Json
        if ($deployment.properties.provisioningState -ne 'Succeeded') {
            throw "Deployment '$DeploymentName' is not in the Succeeded state."
        }
    }
    else {
        $deployments = @(
            az deployment group list `
                --resource-group $ResourceGroup `
                --subscription $resolvedSubscriptionId `
                --output json | ConvertFrom-Json
        )
        $deployment = $deployments |
            Where-Object {
                $_.properties.provisioningState -eq 'Succeeded' -and
                $null -ne $_.properties.outputs -and
                $null -ne $_.properties.outputs.PSObject.Properties['runnerVaultName'] -and
                $null -ne $_.properties.outputs.PSObject.Properties['workloadResourceId']
            } |
            Sort-Object { [DateTimeOffset]$_.properties.timestamp } -Descending |
            Select-Object -First 1
    }
    if ($null -eq $deployment) {
        throw (
            "No successful infrastructure deployment with the required outputs was found in " +
            "resource group '$ResourceGroup'."
        )
    }
    $DeploymentOutputsObject = $deployment.properties.outputs
    $sourceDeployment = [string]$deployment.name
}

$requiredOutputs = @(
    'appUrl',
    'crlUrl',
    'logAnalyticsWorkspaceName',
    'keyVaultPrivateEndpointName',
    'publisherClientId',
    'publisherIdentityName',
    'publisherPrincipalId',
    'publisherResourceId',
    'runnerOutboundIpAddress',
    'runnerSubnetId',
    'runnerVaultName',
    'staticWebAppName',
    'workloadClientId',
    'workloadIdentityName',
    'workloadPrincipalId',
    'workloadResourceId',
    'virtualNetworkName'
)
$resolvedOutputs = [ordered]@{}
foreach ($name in $requiredOutputs) {
    $resolvedOutputs[$name] = Get-DeploymentOutputValue `
        -Outputs $DeploymentOutputsObject `
        -Name $name
}

$staticWebApp = az staticwebapp show `
    --name ([string]$resolvedOutputs.staticWebAppName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
$expectedAppUrl = "https://$($staticWebApp.defaultHostname)/"
$expectedCrlUrl = "http://$($staticWebApp.defaultHostname)/crl/entra-cba-lab.crl"
Assert-ExactValue `
    -Name 'Static Web App name' `
    -Expected ([string]$resolvedOutputs.staticWebAppName) `
    -Actual ([string]$staticWebApp.name) `
    -CaseSensitive
Assert-ExactValue `
    -Name 'Static Web App URL' `
    -Expected $expectedAppUrl `
    -Actual ([string]$resolvedOutputs.appUrl) `
    -CaseSensitive
Assert-ExactValue `
    -Name 'CRL URL' `
    -Expected $expectedCrlUrl `
    -Actual ([string]$resolvedOutputs.crlUrl) `
    -CaseSensitive

$workloadIdentity = az identity show `
    --name ([string]$resolvedOutputs.workloadIdentityName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
$publisherIdentity = az identity show `
    --name ([string]$resolvedOutputs.publisherIdentityName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
foreach ($identityContract in @(
    @{
        label = 'Workload identity'
        live = $workloadIdentity
        clientId = [string]$resolvedOutputs.workloadClientId
        principalId = [string]$resolvedOutputs.workloadPrincipalId
        resourceId = [string]$resolvedOutputs.workloadResourceId
    },
    @{
        label = 'Publisher identity'
        live = $publisherIdentity
        clientId = [string]$resolvedOutputs.publisherClientId
        principalId = [string]$resolvedOutputs.publisherPrincipalId
        resourceId = [string]$resolvedOutputs.publisherResourceId
    }
)) {
    Assert-ExactValue `
        -Name "$($identityContract.label) client ID" `
        -Expected $identityContract.clientId `
        -Actual ([string]$identityContract.live.clientId)
    Assert-ExactValue `
        -Name "$($identityContract.label) principal ID" `
        -Expected $identityContract.principalId `
        -Actual ([string]$identityContract.live.principalId)
    Assert-ExactValue `
        -Name "$($identityContract.label) resource ID" `
        -Expected $identityContract.resourceId `
        -Actual ([string]$identityContract.live.id)
}

$workspace = az monitor log-analytics workspace show `
    --workspace-name ([string]$resolvedOutputs.logAnalyticsWorkspaceName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
Assert-ExactValue `
    -Name 'Log Analytics workspace name' `
    -Expected ([string]$resolvedOutputs.logAnalyticsWorkspaceName) `
    -Actual ([string]$workspace.name) `
    -CaseSensitive

$virtualNetwork = az network vnet show `
    --name ([string]$resolvedOutputs.virtualNetworkName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
$runnerSubnet = az network vnet subnet show `
    --name 'snet-github-runner' `
    --vnet-name ([string]$resolvedOutputs.virtualNetworkName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
$privateEndpointSubnet = az network vnet subnet show `
    --name 'snet-private-endpoints' `
    --vnet-name ([string]$resolvedOutputs.virtualNetworkName) `
    --resource-group $ResourceGroup `
    --subscription $resolvedSubscriptionId `
    --output json | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace([string]$virtualNetwork.location)) {
    throw 'The live virtual network did not return a deployment location.'
}
Assert-ExactValue `
    -Name 'Runner subnet resource ID' `
    -Expected ([string]$runnerSubnet.id) `
    -Actual ([string]$resolvedOutputs.runnerSubnetId)

$state = [ordered]@{
    subscriptionId = $resolvedSubscriptionId
    subscriptionName = [string]$account.name
    tenantId = [string]$account.tenantId
    resourceGroup = [string]$resourceGroupObject.name
    location = [string]$virtualNetwork.location
    deploymentName = $sourceDeployment
    importedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    outputs = [ordered]@{}
}
foreach ($name in $requiredOutputs) {
    $state.outputs[$name] = [ordered]@{
        type = 'String'
        value = [string]$resolvedOutputs[$name]
    }
}

$networkContract = Get-RunnerNetworkContract -Infrastructure ([pscustomobject]$state)
Assert-ExactValue `
    -Name 'Virtual network resource ID' `
    -Expected ([string]$virtualNetwork.id) `
    -Actual ([string]$networkContract.virtualNetworkId)
Assert-ExactValue `
    -Name 'Private Endpoint subnet resource ID' `
    -Expected ([string]$privateEndpointSubnet.id) `
    -Actual ([string]$networkContract.privateEndpointSubnetId)

$publisherOperationStatePath = Join-Path `
    (Split-Path -Parent $PSScriptRoot) `
    '.lab-state\publisher-operation.json'
$repairableAssignmentId = Get-RecordedPublisherAssignmentId `
    -OperationStatePath $publisherOperationStatePath `
    -PublisherPrincipalId ([string]$publisherIdentity.principalId) `
    -VaultResourceId ([string]$networkContract.keyVaultId)
Assert-LabVaultRbac `
    -Outputs ([pscustomobject]$state.outputs) `
    -ResourceGroup $ResourceGroup `
    -AllowRepairableLabAssignments `
    -RepairableAssignmentId $repairableAssignmentId | Out-Null

$dependentStateNames = @(
    'application-operation.json'
    'application.json'
    'conditional-access-isolation.json'
    'conditional-access-operation.json'
    'conditional-access.json'
    'credentials.json'
    'entra-baseline-operation.json'
    'entra-baseline-context.json'
    'entra-operation.json'
    'entra-teardown.json'
    'entra.json'
    'github.json'
    'pki-baseline.json'
    'pki.json'
    'runner-operation.json'
    'runner.json'
    'x509-policy-baseline.json'
)
$dependentStatePaths = @($dependentStateNames | ForEach-Object {
    Join-Path $stateDirectory $_
} | Where-Object {
    Test-Path -LiteralPath $_
})
$bindingDiffers = $false
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    $existingInfrastructure = Get-Content -LiteralPath $StatePath -Raw |
        ConvertFrom-Json
    $bindingDiffers = (
        $existingInfrastructure.subscriptionId -ine $state.subscriptionId -or
        $existingInfrastructure.tenantId -ine $state.tenantId -or
        $existingInfrastructure.resourceGroup -ine $state.resourceGroup -or
        $existingInfrastructure.location -ine $state.location
    )
    foreach ($name in $requiredOutputs) {
        $existingOutput = $existingInfrastructure.outputs.PSObject.Properties[$name]
        if (
            $null -eq $existingOutput -or
            [string]$existingOutput.Value.value -cne [string]$state.outputs[$name].value
        ) {
            $bindingDiffers = $true
        }
    }
}
elseif ($dependentStatePaths.Count -ne 0) {
    $bindingDiffers = $true
}
if ($bindingDiffers -and $dependentStatePaths.Count -ne 0) {
    throw (
        'Refusing to replace infrastructure binding while dependent lab state exists: ' +
        (($dependentStatePaths | Split-Path -Leaf | Sort-Object) -join ', ')
    )
}

Write-InfrastructureStateAtomically -Path $StatePath -State $state
Write-Host "Imported and verified infrastructure state at '$StatePath'."
}
finally {
    $importLock.Dispose()
}
