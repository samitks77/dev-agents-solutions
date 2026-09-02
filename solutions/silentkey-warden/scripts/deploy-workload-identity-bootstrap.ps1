<#
.SYNOPSIS
Deploys the silentkey-warden Workload Identity Protection detection layer into an Azure resource group.

.DESCRIPTION
Wraps the ARM deployment so it is repeatable and produces consistent evidence.

What it does:
1) Verifies Azure CLI is available.
2) Targets the requested subscription.
3) Ensures the resource group exists.
4) Validates the template and parameters.
5) Runs What-If, or the real deployment.
6) Prints the outputs the next steps need.
7) Tells you the one thing that is easy to forget: without Entra diagnostic settings,
   every detection stays permanently silent.

Why this script exists:
- Standardizes deployment across demo, pilot, and customer tenants.
- Removes copy/paste drift from long az command lines.
- Ends with an explicit, ordered next-step list rather than a wall of JSON.

.EXAMPLE
./deploy-workload-identity-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -Location eastus2

.EXAMPLE
./deploy-workload-identity-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -Location eastus2 -SocEmailAddress soc@contoso.com

.EXAMPLE
./deploy-workload-identity-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -Location eastus2 -WhatIf
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$Location,

  # Optional SOC distribution address wired into the action group.
  [Parameter(Mandatory = $false)]
  [string]$SocEmailAddress = "",

  [Parameter(Mandatory = $false)]
  [string]$DeploymentName = ("silentkey-warden-" + (Get-Date -Format "yyyyMMdd-HHmmss")),

  [Parameter(Mandatory = $false)]
  [string]$TemplateFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\workload-identity-protection.json"),

  [Parameter(Mandatory = $false)]
  [string]$ParameterFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\workload-identity-protection.parameters.json"),

  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

Write-Step "Step 1/6 - Verifying Azure CLI is available (what: tooling check, why: deployment depends on az)."
az version --output none

Write-Step "Step 2/6 - Targeting subscription $SubscriptionId (what: scope selection, why: prevents deploying to the wrong subscription)."
az account set --subscription $SubscriptionId

Write-Step "Step 3/6 - Ensuring resource group $ResourceGroupName exists in $Location (what: deployment boundary, why: deterministic resource scope)."
az group create --name $ResourceGroupName --location $Location --output table

$extraParameters = @("location=$Location")
if (-not [string]::IsNullOrWhiteSpace($SocEmailAddress)) {
  $extraParameters += "socEmailAddress=$SocEmailAddress"
  Write-Step "SOC notification address will be wired into the action group: $SocEmailAddress"
}
else {
  Write-Step "No SOC address supplied. The action group deploys with no receivers; add them later in the portal."
}

Write-Step "Step 4/6 - Validating template and parameters (what: preflight validation, why: fail fast before deployment)."
az deployment group validate `
  --name "$DeploymentName-validate" `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters $extraParameters `
  --output none
Write-Host "  Template validated." -ForegroundColor Green

if ($WhatIf) {
  Write-Step "Step 5/6 - Running What-If (what: preview changes, why: safe review before apply)."
  az deployment group what-if `
    --name "$DeploymentName-whatif" `
    --resource-group $ResourceGroupName `
    --template-file $TemplateFile `
    --parameters "@$ParameterFile" `
    --parameters $extraParameters

  Write-Step "Step 6/6 - Completed What-If only. No resources were created."
  return
}

Write-Step "Step 5/6 - Running deployment (what: create/update resources, why: establish the detection layer)."
$deployment = az deployment group create `
  --name $DeploymentName `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters $extraParameters `
  --output json | ConvertFrom-Json

Write-Step "Step 6/6 - Printing key outputs (what: capture integration values, why: needed by the next configuration steps)."
$outputs = $deployment.properties.outputs

Write-Host ""
Write-Host "logAnalyticsWorkspaceName       : $($outputs.logAnalyticsWorkspaceName.value)"
Write-Host "logAnalyticsWorkspaceResourceId : $($outputs.logAnalyticsWorkspaceResourceId.value)"
Write-Host "logAnalyticsCustomerId          : $($outputs.logAnalyticsCustomerId.value)"
Write-Host "actionGroupResourceId           : $($outputs.actionGroupResourceId.value)"
Write-Host "alertRulesDeployed              : $($outputs.alertRulesDeployed.value)"
Write-Host "workbookResourceId              : $($outputs.workbookResourceId.value)"
Write-Host ""

Write-Host "IMPORTANT - the detections are deployed but blind until Entra logs are flowing." -ForegroundColor Yellow
Write-Host "Next steps, in order:" -ForegroundColor Yellow
Write-Host "  1. ./configure-entra-diagnostics.ps1 -WorkspaceResourceId $($outputs.logAnalyticsWorkspaceResourceId.value)" -ForegroundColor Yellow
Write-Host "  2. ./deploy-conditional-access-policy.ps1 -ReportOnly" -ForegroundColor Yellow
Write-Host "  3. ./post-deploy-smoke-test.ps1 -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName" -ForegroundColor Yellow
Write-Host ""

Write-Step "Deployment completed successfully."
