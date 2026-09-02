<#
.SYNOPSIS
Removes every artifact created by invoke-poc-risk-simulation.ps1.

.DESCRIPTION
Reverses the POC in the correct order. Order matters: dismissing risk before deleting the
identity keeps the Identity Protection blade clean, and reverting the Conditional Access
policy before deleting identities avoids blocking yourself out of the deletion calls.

What it does:
1) Finds every app registration matching the POC naming convention.
2) Lists exactly what will be deleted and asks for confirmation.
3) Dismisses the risk state on each associated service principal.
4) Deletes the app registrations, which also removes their service principals.
5) Reminds you about the Conditional Access policy and the Azure resources, which are
   deliberately NOT deleted by this script.

Why the CA policy and Azure resources are not deleted here:
- The policy and the detection layer are usually the parts a customer wants to keep. Only the
  disposable test identities should disappear when the demo ends. Deleting production controls
  by accident is a far worse outcome than leaving a policy behind.

.EXAMPLE
./remove-poc-resources.ps1 -WhatIf

.EXAMPLE
./remove-poc-resources.ps1 -Force
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$NamePrefix = "POC-Test",

  # Also removes the core POC app from the manual walkthrough, if present.
  [Parameter(Mandatory = $false)]
  [string[]]$AdditionalDisplayNames = @("POC-RiskyWorkloadIdentity", "POC-LeakedCredentialTest"),

  [switch]$Force,

  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

Write-Step "Step 1/5 - Verifying context."
az version --output none
$account = az account show --output json | ConvertFrom-Json
Write-Host "  Tenant: $($account.tenantId)"

Write-Step "Step 2/5 - Finding POC app registrations (what: inventory, why: never delete by guess)."
$allApps = az ad app list --all --output json | ConvertFrom-Json

$targets = @($allApps | Where-Object {
    $_.displayName -like "$NamePrefix*" -or $AdditionalDisplayNames -contains $_.displayName
  })

if ($targets.Count -eq 0) {
  Write-Host "  Nothing to remove. No app registrations matched '$NamePrefix*' or the additional names." -ForegroundColor Green
  return
}

Write-Host ""
Write-Host "  The following app registrations (and their service principals) will be deleted:" -ForegroundColor Yellow
foreach ($app in $targets) {
  Write-Host "    - $($app.displayName)  [appId $($app.appId)]"
}
Write-Host ""

if ($WhatIf) {
  Write-Step "WhatIf - nothing was deleted."
  return
}

if (-not $Force) {
  $answer = Read-Host "Type the word 'delete' to remove these $($targets.Count) identities"
  if ($answer -ne "delete") {
    Write-Host "Aborted. Nothing was deleted." -ForegroundColor Yellow
    return
  }
}

Write-Step "Step 3/5 - Dismissing risk state (what: clears Identity Protection, why: leaves the risk blade clean and avoids orphaned risk records)."
foreach ($app in $targets) {
  $sp = az ad sp list --filter "appId eq '$($app.appId)'" --output json 2>$null | ConvertFrom-Json
  $spObject = @($sp) | Select-Object -First 1

  if ($null -eq $spObject) {
    Write-Host "  No service principal for $($app.displayName) - skipping dismiss."
    continue
  }

  $payload = @{ servicePrincipalIds = @($spObject.id) } | ConvertTo-Json -Compress
  $tempFile = New-TemporaryFile
  try {
    Set-Content -Path $tempFile -Value $payload -Encoding utf8
    az rest `
      --method post `
      --url "https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals/dismiss" `
      --body "@$tempFile" `
      --headers "Content-Type=application/json" `
      --output none 2>$null
    Write-Host "  Risk dismissed: $($app.displayName)" -ForegroundColor Green
  }
  catch {
    Write-Host "  Could not dismiss risk for $($app.displayName) - it may not have had any. Continuing." -ForegroundColor DarkGray
  }
  finally {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
  }
}

Write-Step "Step 4/5 - Deleting app registrations (what: removes app + service principal, why: the identities are disposable by design)."
foreach ($app in $targets) {
  az ad app delete --id $app.appId --output none
  Write-Host "  Deleted: $($app.displayName)" -ForegroundColor Green
}

Write-Step "Step 5/5 - Manual follow-ups this script deliberately does NOT perform."
Write-Host ""
Write-Host "  1. Conditional Access policy" -ForegroundColor Yellow
Write-Host "     If you switched it to enforced for the demo, set it back to report-only." -ForegroundColor Yellow
Write-Host "     Protection > Conditional Access > Policies" -ForegroundColor Yellow
Write-Host ""
Write-Host "  2. Azure detection layer (workspace, alert rules, workbook)" -ForegroundColor Yellow
Write-Host "     Left in place on purpose - it is the part worth keeping. To remove it:" -ForegroundColor Yellow
Write-Host "     az group delete --name <resource-group> --yes" -ForegroundColor Yellow
Write-Host ""
Write-Host "  3. Entra diagnostic setting" -ForegroundColor Yellow
Write-Host "     az rest --method delete --url 'https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/silentkey-warden-workload-identity?api-version=2017-04-01-preview'" -ForegroundColor Yellow
Write-Host ""

Write-Step "Cleanup completed. $($targets.Count) identities removed."
