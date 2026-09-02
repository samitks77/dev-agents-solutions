<#
.SYNOPSIS
Validates the silentkey-warden Workload Identity Protection template before any deployment.

.DESCRIPTION
Runs every check that can fail cheaply, in increasing order of cost:

1) Confirms Azure CLI is present.
2) Parses the ARM template and parameter files locally (catches JSON typos with no network call).
3) Confirms every KQL detection referenced by the template exists on disk.
4) Targets the requested subscription.
5) Ensures the resource group exists.
6) Runs an ARM validation pass against Azure.
7) Runs What-If so you can read the change set before committing to it.

Why this script exists:
- A failed deployment halfway through leaves partial resources behind. Validating first is
  cheaper than cleaning up.
- Customer and demo environments are unforgiving; this produces the evidence that the
  template is sound before anyone watches you run it.

.EXAMPLE
./validate-workload-identity-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -Location eastus2

.EXAMPLE
./validate-workload-identity-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -Location eastus2 -SkipAzureChecks
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName = "rg-silentkey-warden",

  [Parameter(Mandatory = $false)]
  [string]$Location = "eastus2",

  [Parameter(Mandatory = $false)]
  [string]$TemplateFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\workload-identity-protection.json"),

  [Parameter(Mandatory = $false)]
  [string]$ParameterFile = (Join-Path $PSScriptRoot "..\templates\azuredeploy\workload-identity-protection.parameters.json"),

  # Runs local-only checks. Useful in CI or on a machine with no Azure session.
  [switch]$SkipAzureChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

function Write-Pass {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "  PASS  $Message" -ForegroundColor Green
}

$failures = 0

Write-Step "Step 1/7 - Checking local files exist (what: path check, why: fail before touching Azure)."
foreach ($file in @($TemplateFile, $ParameterFile)) {
  if (-not (Test-Path $file)) {
    Write-Host "  FAIL  Missing required file: $file" -ForegroundColor Red
    $failures++
  }
  else {
    Write-Pass "Found $(Split-Path $file -Leaf)"
  }
}
if ($failures -gt 0) { throw "Required files missing. Aborting." }

Write-Step "Step 2/7 - Parsing JSON locally (what: syntax validation, why: catches typos with zero cost)."
foreach ($file in @($TemplateFile, $ParameterFile)) {
  try {
    $null = Get-Content -Path $file -Raw | ConvertFrom-Json
    Write-Pass "$(Split-Path $file -Leaf) is valid JSON"
  }
  catch {
    Write-Host "  FAIL  $(Split-Path $file -Leaf) is not valid JSON: $($_.Exception.Message)" -ForegroundColor Red
    $failures++
  }
}
if ($failures -gt 0) { throw "JSON validation failed. Aborting." }

Write-Step "Step 3/7 - Confirming detection library is intact (what: file inventory, why: the README and docs reference these by name)."
$expectedDetections = @(
  "D1-credential-added-to-application.kql",
  "D2-risky-workload-identity-detected.kql",
  "D3-workload-identity-burst-signin.kql",
  "D4-workload-identity-first-time-resource.kql",
  "D5-workload-identity-blocked-by-ca.kql",
  "D6-report-only-enforcement-readiness.kql"
)
$detectionDir = Join-Path $PSScriptRoot "..\detections"
foreach ($detection in $expectedDetections) {
  $path = Join-Path $detectionDir $detection
  if (Test-Path $path) {
    Write-Pass "Detection present: $detection"
  }
  else {
    Write-Host "  FAIL  Missing detection: $detection" -ForegroundColor Red
    $failures++
  }
}
if ($failures -gt 0) { throw "Detection library incomplete. Aborting." }

if ($SkipAzureChecks) {
  Write-Step "Steps 4-7 skipped (-SkipAzureChecks). Local validation passed."
  return
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
  throw "SubscriptionId is required unless -SkipAzureChecks is specified."
}

Write-Step "Step 4/7 - Verifying Azure CLI is available (what: tooling check, why: every remaining step depends on az)."
az version --output none
Write-Pass "Azure CLI responded"

Write-Step "Step 5/7 - Targeting subscription $SubscriptionId (what: scope selection, why: prevents validating against the wrong subscription)."
az account set --subscription $SubscriptionId
Write-Pass "Subscription context set"

Write-Step "Step 6/7 - Ensuring resource group $ResourceGroupName exists in $Location (what: deployment boundary, why: validation needs a real scope)."
az group create --name $ResourceGroupName --location $Location --output none
Write-Pass "Resource group ready"

Write-Step "Step 7/7 - Running ARM validation and What-If (what: server-side preflight, why: surfaces schema and expression errors before deployment)."
az deployment group validate `
  --name "silentkey-warden-validate" `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters location=$Location `
  --output none
Write-Pass "Template validated by Azure Resource Manager"

az deployment group what-if `
  --name "silentkey-warden-whatif" `
  --resource-group $ResourceGroupName `
  --template-file $TemplateFile `
  --parameters "@$ParameterFile" `
  --parameters location=$Location

Write-Step "Validation completed. Review the What-If output above, then run deploy-workload-identity-bootstrap.ps1."
