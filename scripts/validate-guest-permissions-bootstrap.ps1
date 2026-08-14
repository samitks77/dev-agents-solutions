<#
.SYNOPSIS
Validates Guest Permissions ARM template and parameter file.

.DESCRIPTION
What this script does:
1) Confirms template and parameter files exist.
2) Parses both files as JSON locally.
3) Confirms required parameter keys are present.
4) Optionally performs Azure-side template validation.

Why this script exists:
- Gives quick local confidence before deployment.
- Reduces avoidable runtime deployment failures.

.EXAMPLE
.\validate-guest-permissions-bootstrap.ps1

.EXAMPLE
.\validate-guest-permissions-bootstrap.ps1 -ValidateInAzure -SubscriptionId <sub> -ResourceGroupName rg-guest-permissions -Location eastus2
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$TemplateFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\guest-permissions-solution.json"),

  [Parameter(Mandatory = $false)]
  [string]$ParameterFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\guest-permissions-solution.parameters.json"),

  [switch]$ValidateInAzure,

  [string]$SubscriptionId,
  [string]$ResourceGroupName,
  [string]$Location = "eastus2"
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

Write-Step "Step 1/4 - Verifying input files exist (what: path check, why: avoid invalid-file failures)."
if (-not (Test-Path $TemplateFile)) {
  throw "Template file not found: $TemplateFile"
}
if (-not (Test-Path $ParameterFile)) {
  throw "Parameter file not found: $ParameterFile"
}

Write-Step "Step 2/4 - Parsing JSON locally (what: syntax validation, why: catch malformed JSON early)."
$template = Get-Content -Path $TemplateFile -Raw | ConvertFrom-Json
$parameters = Get-Content -Path $ParameterFile -Raw | ConvertFrom-Json

Write-Step "Step 3/4 - Validating required parameter keys (what: schema expectation check, why: reduce deployment-time parameter errors)."
$requiredParameterKeys = @(
  "location",
  "managedIdentityName",
  "logAnalyticsWorkspaceName",
  "containerAppsEnvironmentName",
  "grafanaName",
  "fileShareName",
  "grafanaOperatorObjectId"
)

foreach ($key in $requiredParameterKeys) {
  if (-not $template.parameters.PSObject.Properties.Name.Contains($key)) {
    throw "Required template parameter is missing: $key"
  }
  if (-not $parameters.parameters.PSObject.Properties.Name.Contains($key)) {
    throw "Required parameter file value is missing: $key"
  }
}

if (-not $ValidateInAzure) {
  Write-Step "Step 4/4 - Local validation complete (what: static checks done, why: fast preflight in CI/local workflows)."
  return
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
  throw "-SubscriptionId is required when -ValidateInAzure is used."
}
if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
  throw "-ResourceGroupName is required when -ValidateInAzure is used."
}

Write-Step "Step 4/4 - Running Azure validation (what: platform-level preflight, why: confirms deployability in target subscription)."
az version --output none
az account set --subscription $SubscriptionId
az group create --name $ResourceGroupName --location $Location --output none

az deployment group validate `
  --name "guest-permissions-validate-$(Get-Date -Format yyyyMMddHHmmss)" `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters location=$Location `
  --output table

Write-Step "Validation completed successfully."
