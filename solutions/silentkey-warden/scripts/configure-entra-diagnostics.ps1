<#
.SYNOPSIS
Streams Microsoft Entra ID logs into the silentkey-warden Log Analytics workspace.

.DESCRIPTION
This is the step everyone forgets, and the reason a freshly deployed detection layer
reports nothing.

Entra ID diagnostic settings are a TENANT-level resource (microsoft.aadiam), not a
subscription or resource group resource. They cannot be created by the ARM template that
deploys the workspace, so they are configured here instead.

What it does:
1) Verifies Azure CLI is available and resolves the signed-in tenant.
2) Builds the diagnostic setting payload for the categories this solution needs.
3) Writes the setting at tenant scope via the ARM REST API.
4) Reads the setting back and prints the enabled categories as proof.

Categories enabled and why each one is required:
  AuditLogs                   D1 - credential additions to app registrations
  ServicePrincipalSignInLogs  D3, D4, D5, D6 - all token issuance telemetry
  RiskyServicePrincipals      Workbook - current risk state per identity
  ServicePrincipalRiskEvents  D2 - individual risk detections
  ManagedIdentitySignInLogs   Optional - extends coverage to managed identities

Permissions required:
- Security Administrator or Global Administrator in the tenant.

Cost note:
- ServicePrincipalSignInLogs is the highest-volume category here. In a large tenant it can
  be the dominant ingestion cost. Set `dailyQuotaGb` on the workspace before enabling it in
  production, and review after the first full day.

.EXAMPLE
./configure-entra-diagnostics.ps1 -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/rg-silentkey-warden/providers/Microsoft.OperationalInsights/workspaces/law-silentkey-warden"

.EXAMPLE
./configure-entra-diagnostics.ps1 -WorkspaceResourceId "<id>" -IncludeManagedIdentitySignInLogs -WhatIf
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$WorkspaceResourceId,

  [Parameter(Mandatory = $false)]
  [string]$SettingName = "silentkey-warden-workload-identity",

  # Managed identity sign-ins are a separate, often high-volume category. Off by default.
  [switch]$IncludeManagedIdentitySignInLogs,

  # Prints the payload and target without writing anything.
  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

Write-Step "Step 1/4 - Verifying Azure CLI and resolving tenant (what: context check, why: diagnostic settings are written at tenant scope)."
az version --output none
$account = az account show --output json | ConvertFrom-Json
Write-Host "  Tenant : $($account.tenantId)"
Write-Host "  Signed in as : $($account.user.name)"

Write-Step "Step 2/4 - Building diagnostic setting payload (what: category selection, why: each category feeds a specific detection)."
$logCategories = @(
  @{ category = "AuditLogs"; enabled = $true },
  @{ category = "ServicePrincipalSignInLogs"; enabled = $true },
  @{ category = "RiskyServicePrincipals"; enabled = $true },
  @{ category = "ServicePrincipalRiskEvents"; enabled = $true }
)

if ($IncludeManagedIdentitySignInLogs) {
  $logCategories += @{ category = "ManagedIdentitySignInLogs"; enabled = $true }
  Write-Host "  Including ManagedIdentitySignInLogs (extends coverage to managed identities)."
}

foreach ($entry in $logCategories) {
  Write-Host "  Enabling category: $($entry.category)"
}

$payload = @{
  properties = @{
    workspaceId = $WorkspaceResourceId
    logs        = $logCategories
  }
}

$payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress
$uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/$SettingName" + "?api-version=2017-04-01-preview"

if ($WhatIf) {
  Write-Step "WhatIf - no changes written."
  Write-Host "  PUT $uri"
  Write-Host "  Body: $payloadJson"
  return
}

Write-Step "Step 3/4 - Writing tenant diagnostic setting '$SettingName' (what: enables log streaming, why: without it every detection stays silent)."
$tempFile = New-TemporaryFile
try {
  Set-Content -Path $tempFile -Value $payloadJson -Encoding utf8
  az rest --method put --url $uri --body "@$tempFile" --headers "Content-Type=application/json" --output none
  Write-Host "  Diagnostic setting written." -ForegroundColor Green
}
finally {
  Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

Write-Step "Step 4/4 - Reading the setting back (what: verification, why: confirms the write actually took effect)."
$current = az rest --method get --url $uri --output json | ConvertFrom-Json
$enabled = $current.properties.logs | Where-Object { $_.enabled -eq $true } | ForEach-Object { $_.category }
Write-Host "  Enabled categories: $($enabled -join ', ')" -ForegroundColor Green

Write-Host ""
Write-Host "Entra ID logs are now streaming to the workspace." -ForegroundColor Yellow
Write-Host "Expect a delay before the first rows land:" -ForegroundColor Yellow
Write-Host "  AuditLogs / sign-in logs : 15-30 minutes for the first ingestion" -ForegroundColor Yellow
Write-Host "  D4 first-time-resource   : needs 14 days of history before it is meaningful" -ForegroundColor Yellow
Write-Host ""
Write-Step "Configuration completed."
