[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Subscription,
    [Parameter(Mandatory)][string]$ExpectedTenantId,
    [string]$ResourceGroup = 'rg-entra-cba-playwright-poc-eus2',
    [string]$Location = 'eastus2',
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$templateFile = Join-Path $labRoot 'infra\main.bicep'
. (Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1')

function Assert-LabVaultRbac {
    param(
        [Parameter(Mandatory)][object]$Outputs,
        [switch]$RepairLegacyAssignments
    )

    $vaultName = $Outputs.runnerVaultName.value
    $workloadPrincipalId = $Outputs.workloadPrincipalId.value
    if (-not $vaultName -or -not $workloadPrincipalId) {
        throw 'Infrastructure outputs do not identify the runner vault and workload principal.'
    }
    $vault = az keyvault show `
        --name $vaultName `
        --resource-group $ResourceGroup `
        --output json | ConvertFrom-Json

    $secretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    $directOfficerAssignments = @(
        az role assignment list `
            --scope $vault.id `
            --role $secretsOfficerRoleId `
            --output json | ConvertFrom-Json
    ) | Where-Object { $_.scope -eq $vault.id }
    if ($RepairLegacyAssignments) {
        foreach ($assignment in $directOfficerAssignments) {
            az role assignment delete --ids $assignment.id --output none
        }
        $revocationDeadline = (Get-Date).AddMinutes(2)
        do {
            $directOfficerAssignments = @(
                az role assignment list `
                    --scope $vault.id `
                    --role $secretsOfficerRoleId `
                    --output json | ConvertFrom-Json
            ) | Where-Object { $_.scope -eq $vault.id }
            if ($directOfficerAssignments.Count -ne 0) {
                Start-Sleep -Seconds 5
            }
        } while ($directOfficerAssignments.Count -ne 0 -and (Get-Date) -lt $revocationDeadline)
    }
    if ($directOfficerAssignments.Count -ne 0) {
        throw 'The lab vault retains a direct Key Vault Secrets Officer assignment.'
    }

    $mutationAssignments = @(Get-KeyVaultSecretMutationAssignments `
        -PrincipalId $workloadPrincipalId `
        -VaultResourceId $vault.id)
    if ($mutationAssignments.Count -ne 0) {
        $roleSummary = $mutationAssignments | ForEach-Object {
            "'$($_.roleName)' at '$($_.scope)'"
        }
        throw "The GitHub workload identity can mutate Key Vault secrets through $($roleSummary -join ', ')."
    }

    $secretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
    $readerAssignments = @(
        az role assignment list `
            --assignee $workloadPrincipalId `
            --scope $vault.id `
            --only-show-errors `
            --output json | ConvertFrom-Json
    ) | Where-Object {
        $_.scope -eq $vault.id -and
        $_.roleDefinitionId.EndsWith(
            "/$secretsUserRoleId",
            [StringComparison]::OrdinalIgnoreCase
        )
    }
    if ($readerAssignments.Count -ne 1) {
        throw 'The GitHub workload identity must have exactly one direct Key Vault Secrets User assignment.'
    }
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
    az group create `
        --name $ResourceGroup `
        --location $Location `
        --tags environment=poc workload=entra-cba-playwright managedBy=bicep expiresOn=2026-09-30 `
        --output none
}

New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null

$deploymentName = "entra-cba-poc-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"
if ($WhatIf) {
    az deployment group what-if `
        --name $deploymentName `
        --resource-group $ResourceGroup `
        --template-file $templateFile `
        --parameters location=$Location
    if ($LASTEXITCODE -ne 0) {
        throw "Infrastructure what-if failed with exit code $LASTEXITCODE."
    }
    $existingStatePath = Join-Path $stateDirectory 'infrastructure.json'
    if (Test-Path -LiteralPath $existingStatePath) {
        $existingState = Get-Content -LiteralPath $existingStatePath -Raw | ConvertFrom-Json
        Assert-LabVaultRbac -Outputs $existingState.outputs
    }
    Write-Host "Infrastructure what-if succeeded in '$ResourceGroup'."
    return
}

az deployment group create `
    --name $deploymentName `
    --resource-group $ResourceGroup `
    --template-file $templateFile `
    --parameters location=$Location `
    --output none

$outputs = az deployment group show `
    --name $deploymentName `
    --resource-group $ResourceGroup `
    --query properties.outputs `
    --output json | ConvertFrom-Json

Assert-LabVaultRbac -Outputs $outputs -RepairLegacyAssignments

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
