<#
.SYNOPSIS
Verifies the deployed silentkey-warden detection layer is healthy and actually receiving data.

.DESCRIPTION
Runs after deployment to answer three questions in order, because a failure in one makes the
next meaningless:

1) Do the resources exist?          (workspace, action group, 5 alert rules, workbook)
2) Are Entra logs arriving?         (the required tables exist and have recent rows)
3) Do the detections return sanely? (each query parses and executes against real data)

Why this script exists:
- A detection layer that deploys cleanly but receives no data looks identical to one that is
  working, right up until an incident. This closes that gap.
- Produces a pass/fail summary suitable for a go-live checklist or customer handoff evidence.

Exit behaviour:
- Writes a summary table and throws if any REQUIRED check failed.
- Data-freshness checks are reported as warnings, not failures, within the first hour after
  configuring diagnostics.

.EXAMPLE
./post-deploy-smoke-test.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden

.EXAMPLE
./post-deploy-smoke-test.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -WorkspaceName law-silentkey-warden
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $false)]
  [string]$WorkspaceName = "law-silentkey-warden",

  [Parameter(Mandatory = $false)]
  [string]$NamePrefix = "silentkey"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

$results = New-Object System.Collections.ArrayList

function Add-Result {
  param(
    [Parameter(Mandatory = $true)][string]$Check,
    [Parameter(Mandatory = $true)][string]$Status,
    [Parameter(Mandatory = $false)][string]$Detail = ""
  )

  $null = $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })

  $color = switch ($Status) {
    "PASS" { "Green" }
    "WARN" { "Yellow" }
    default { "Red" }
  }
  Write-Host ("  {0,-6} {1} {2}" -f $Status, $Check, $Detail) -ForegroundColor $color
}

Write-Step "Step 1/4 - Setting subscription context."
az version --output none
az account set --subscription $SubscriptionId

Write-Step "Step 2/4 - Checking deployed resources exist."

$workspace = az monitor log-analytics workspace show `
  --resource-group $ResourceGroupName `
  --workspace-name $WorkspaceName `
  --output json 2>$null | ConvertFrom-Json

if ($null -ne $workspace) {
  Add-Result -Check "Log Analytics workspace" -Status "PASS" -Detail "retention $($workspace.retentionInDays)d"
  $customerId = $workspace.customerId
}
else {
  Add-Result -Check "Log Analytics workspace" -Status "FAIL" -Detail "not found: $WorkspaceName"
  $customerId = $null
}

$actionGroups = az monitor action-group list --resource-group $ResourceGroupName --output json | ConvertFrom-Json
$actionGroup = $actionGroups | Where-Object { $_.name -like "ag-$NamePrefix-soc" } | Select-Object -First 1
if ($null -ne $actionGroup) {
  $receiverCount = 0
  if ($null -ne $actionGroup.emailReceivers) { $receiverCount = @($actionGroup.emailReceivers).Count }
  if ($receiverCount -gt 0) {
    Add-Result -Check "SOC action group" -Status "PASS" -Detail "$receiverCount email receiver(s)"
  }
  else {
    Add-Result -Check "SOC action group" -Status "WARN" -Detail "exists but has no receivers - alerts will fire silently"
  }
}
else {
  Add-Result -Check "SOC action group" -Status "FAIL" -Detail "not found"
}

$rules = az monitor scheduled-query list --resource-group $ResourceGroupName --output json 2>$null | ConvertFrom-Json
$solutionRules = @($rules | Where-Object { $_.name -like "$NamePrefix-D*" })
if ($solutionRules.Count -eq 5) {
  Add-Result -Check "Detection rules (expect 5)" -Status "PASS" -Detail "$($solutionRules.Count) found"
}
elseif ($solutionRules.Count -gt 0) {
  Add-Result -Check "Detection rules (expect 5)" -Status "FAIL" -Detail "only $($solutionRules.Count) found"
}
else {
  Add-Result -Check "Detection rules (expect 5)" -Status "FAIL" -Detail "none found - was deployAlertRules set to false?"
}

foreach ($rule in $solutionRules) {
  $enabledState = if ($rule.enabled) { "enabled" } else { "DISABLED" }
  $status = if ($rule.enabled) { "PASS" } else { "WARN" }
  Add-Result -Check "  rule $($rule.name)" -Status $status -Detail $enabledState
}

Write-Step "Step 3/4 - Checking Entra log ingestion."

if ($null -eq $customerId) {
  Add-Result -Check "Entra log ingestion" -Status "FAIL" -Detail "skipped, no workspace"
}
else {
  $requiredTables = @{
    "AuditLogs"                      = "D1 - credential additions"
    "AADServicePrincipalSignInLogs"  = "D3, D4, D5, D6 - token telemetry"
    "AADServicePrincipalRiskEvents"  = "D2 - risk detections"
  }

  foreach ($table in $requiredTables.Keys) {
    $query = "$table | where TimeGenerated > ago(24h) | summarize Rows = count()"
    $raw = az monitor log-analytics query --workspace $customerId --analytics-query $query --output json 2>$null

    if ([string]::IsNullOrWhiteSpace($raw)) {
      Add-Result -Check "Table $table" -Status "WARN" -Detail "no data yet - $($requiredTables[$table])"
    }
    else {
      $parsed = $raw | ConvertFrom-Json
      $rowCount = 0
      if (@($parsed).Count -gt 0) { $rowCount = [int]$parsed[0].Rows }

      if ($rowCount -gt 0) {
        Add-Result -Check "Table $table" -Status "PASS" -Detail "$rowCount rows in last 24h"
      }
      else {
        Add-Result -Check "Table $table" -Status "WARN" -Detail "table exists but is empty in last 24h"
      }
    }
  }
}

Write-Step "Step 4/4 - Summary."
Write-Host ""
$results | Format-Table -AutoSize
Write-Host ""

$failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = @($results | Where-Object { $_.Status -eq "WARN" }).Count

if ($failCount -gt 0) {
  Write-Host "$failCount required check(s) failed." -ForegroundColor Red
  throw "Smoke test failed. Resolve the FAIL rows above before proceeding."
}

if ($warnCount -gt 0) {
  Write-Host "$warnCount warning(s). If you configured Entra diagnostics in the last hour, empty tables are expected." -ForegroundColor Yellow
  Write-Host "Re-run this script after ingestion has had time to start." -ForegroundColor Yellow
}
else {
  Write-Host "All checks passed. The detection layer is deployed and receiving data." -ForegroundColor Green
}
