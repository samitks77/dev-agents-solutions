<#
.SYNOPSIS
Deploys the Guest Permissions infrastructure bootstrap into an Azure resource group.

.DESCRIPTION
This script wraps ARM deployment for repeatability and handoff quality.

What it does:
1) Validates local prerequisites.
2) Targets the requested subscription.
3) Ensures the resource group exists.
4) Validates the template + parameters.
5) Runs What-If or actual deployment.
6) Prints key outputs needed by downstream runtime setup.

Why this script exists:
- Standardizes deployment for internal and customer demos.
- Reduces operator drift and copy/paste errors.
- Produces consistent deployment evidence.

.EXAMPLE
.\deploy-guest-permissions-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-guest-permissions -Location eastus2

.EXAMPLE
.\deploy-guest-permissions-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-guest-permissions -Location eastus2 -WhatIf
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$Location,

  [Parameter(Mandatory = $false)]
  [string]$DeploymentName = ("guest-permissions-bootstrap-" + (Get-Date -Format "yyyyMMdd-HHmmss")),

  [Parameter(Mandatory = $false)]
  [string]$TemplateFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\guest-permissions-solution.json"),

  [Parameter(Mandatory = $false)]
  [string]$ParameterFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\guest-permissions-solution.parameters.json"),

  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Message
  )

  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

Write-Step "Step 1/6 - Verifying Azure CLI is available (what: tooling check, why: deployment depends on az)."
az version --output none

Write-Step "Step 2/6 - Targeting subscription $SubscriptionId (what: scope selection, why: prevents deploying to wrong subscription)."
az account set --subscription $SubscriptionId

Write-Step "Step 3/6 - Ensuring resource group $ResourceGroupName exists in $Location (what: deployment boundary, why: deterministic resource scope)."
az group create --name $ResourceGroupName --location $Location --output table

Write-Step "Step 4/6 - Validating template and parameters (what: preflight validation, why: fail fast before deployment)."
az deployment group validate `
  --name "$DeploymentName-validate" `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters location=$Location `
  --output table

if ($WhatIf) {
  Write-Step "Step 5/6 - Running What-If (what: preview changes, why: safe review before apply)."
  az deployment group what-if `
    --name "$DeploymentName-whatif" `
    --resource-group $ResourceGroupName `
    --template-file $TemplateFile `
    --parameters "@$ParameterFile" `
    --parameters location=$Location

  Write-Step "Step 6/6 - Completed What-If only (no resources created)."
  return
}

Write-Step "Step 5/6 - Running deployment (what: create/update resources, why: establish bootstrap platform)."
$deployment = az deployment group create `
  --name $DeploymentName `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters location=$Location `
  --output json | ConvertFrom-Json

Write-Step "Step 6/6 - Printing key outputs (what: capture integration values, why: needed for runtime and dashboard wiring)."
$outputs = $deployment.properties.outputs

Write-Host "managedIdentityClientId     : $($outputs.managedIdentityClientId.value)"
Write-Host "managedIdentityPrincipalId  : $($outputs.managedIdentityPrincipalId.value)"
Write-Host "logAnalyticsWorkspaceId     : $($outputs.logAnalyticsWorkspaceId.value)"
Write-Host "containerAppsEnvironmentId  : $($outputs.containerAppsEnvironmentId.value)"
Write-Host "storageAccountName          : $($outputs.storageAccountName.value)"
Write-Host "fileShareName               : $($outputs.fileShareName.value)"
Write-Host "grafanaName                 : $($outputs.grafanaName.value)"
Write-Host "grafanaEndpoint             : $($outputs.grafanaEndpoint.value)"

Write-Step "Deployment completed successfully."
