<#
.SYNOPSIS
Creates the workload identity Conditional Access policy in report-only mode.

.DESCRIPTION
Creates the Conditional Access policy described in Step 5 of the POC guide, via Microsoft
Graph, so the configuration is version-controlled rather than clicked together in a portal.

What it does:
1) Verifies Azure CLI and Graph access.
2) Resolves the target service principals (either an explicit list, or every SP in the tenant).
3) Builds the policy body from policies/ca-block-risky-workload-identities.json.
4) Creates the policy - ALWAYS in report-only state unless -Enforce is passed explicitly.
5) Prints the policy id and the exact command to enforce it later.

Why report-only is the default:
- Report-only logs the Conditional Access decision without blocking the sign-in. A blocking
  policy on workload identities can take down production integrations instantly, and the
  identities affected are usually the ones nobody has an owner for.
- Run detection D6 (report-only enforcement readiness) for at least 7 days before enforcing.
  It tells you exactly which identities would have been blocked.

Permissions required:
- Policy.ReadWrite.ConditionalAccess and Application.Read.All
- Conditional Access Administrator, Security Administrator, or Global Administrator
- Microsoft Entra Workload Identities Premium license (standalone SKU)

.EXAMPLE
./deploy-conditional-access-policy.ps1

.EXAMPLE
./deploy-conditional-access-policy.ps1 -ServicePrincipalIds @("<sp-object-id-1>","<sp-object-id-2>")

.EXAMPLE
./deploy-conditional-access-policy.ps1 -ScopeAllServicePrincipals -WhatIf
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$DisplayName = "silentkey-warden - Block Risky Workload Identities",

  # Explicit list of service principal OBJECT ids to scope the policy to.
  [Parameter(Mandatory = $false)]
  [string[]]$ServicePrincipalIds = @(),

  # Scope to every service principal in the tenant. Powerful, and correspondingly risky.
  [switch]$ScopeAllServicePrincipals,

  [Parameter(Mandatory = $false)]
  [ValidateSet("high", "medium", "low")]
  [string[]]$RiskLevels = @("high", "medium"),

  # Creates the policy in enforced state. Do not use before running detection D6.
  [switch]$Enforce,

  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

Write-Step "Step 1/5 - Verifying Azure CLI and Graph access (what: tooling check, why: policy creation goes through Microsoft Graph)."
az version --output none
$account = az account show --output json | ConvertFrom-Json
Write-Host "  Tenant : $($account.tenantId)"

Write-Step "Step 2/5 - Resolving policy scope (what: choose which identities the policy evaluates, why: scope is the single biggest blast-radius control)."
if ($ScopeAllServicePrincipals) {
  $includeServicePrincipals = @("ServicePrincipalsInMyTenant")
  Write-Host "  Scope: EVERY service principal in the tenant." -ForegroundColor Yellow
  Write-Host "  This is the production end-state, but verify with detection D6 before enforcing." -ForegroundColor Yellow
}
elseif ($ServicePrincipalIds.Count -gt 0) {
  $includeServicePrincipals = $ServicePrincipalIds
  Write-Host "  Scope: $($ServicePrincipalIds.Count) explicitly named service principal(s)."
}
else {
  throw "Specify either -ServicePrincipalIds or -ScopeAllServicePrincipals. Refusing to guess the scope of a blocking policy."
}

$state = if ($Enforce) { "enabled" } else { "enabledForReportingButNotEnforced" }
if ($Enforce) {
  Write-Host "  State: ENFORCED. Risky identities will be denied tokens immediately." -ForegroundColor Red
}
else {
  Write-Host "  State: report-only. Decisions are logged, nothing is blocked." -ForegroundColor Green
}

Write-Step "Step 3/5 - Building policy body (what: assemble Graph payload, why: keeps the policy definition in source control)."
$policy = @{
  displayName    = $DisplayName
  state          = $state
  conditions     = @{
    clientApplications        = @{
      includeServicePrincipals = $includeServicePrincipals
      excludeServicePrincipals = @()
    }
    applications              = @{
      includeApplications = @("All")
    }
    servicePrincipalRiskLevels = $RiskLevels
  }
  grantControls  = @{
    operator          = "OR"
    builtInControls   = @("block")
  }
}

$policyJson = $policy | ConvertTo-Json -Depth 10
Write-Host "  Risk levels evaluated: $($RiskLevels -join ', ')"
Write-Host "  Grant control: block"

if ($WhatIf) {
  Write-Step "WhatIf - no policy created. Payload below."
  Write-Host $policyJson
  return
}

Write-Step "Step 4/5 - Creating the Conditional Access policy (what: POST to Graph, why: applies the control)."
$tempFile = New-TemporaryFile
try {
  Set-Content -Path $tempFile -Value ($policy | ConvertTo-Json -Depth 10 -Compress) -Encoding utf8
  $created = az rest `
    --method post `
    --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    --body "@$tempFile" `
    --headers "Content-Type=application/json" `
    --output json | ConvertFrom-Json
}
finally {
  Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
}

Write-Step "Step 5/5 - Policy created (what: confirmation, why: you need the id for the enforce step)."
Write-Host ""
Write-Host "  Policy id      : $($created.id)"
Write-Host "  Display name   : $($created.displayName)"
Write-Host "  State          : $($created.state)"
Write-Host ""

if (-not $Enforce) {
  Write-Host "The policy is in report-only mode. Before enforcing:" -ForegroundColor Yellow
  Write-Host "  1. Let it run for at least 7 days." -ForegroundColor Yellow
  Write-Host "  2. Run detections/D6-report-only-enforcement-readiness.kql." -ForegroundColor Yellow
  Write-Host "  3. Confirm WouldHaveBlocked is zero, or that every identity listed is expected." -ForegroundColor Yellow
  Write-Host "  4. Then enforce:" -ForegroundColor Yellow
  Write-Host "     az rest --method patch --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($created.id)' --body '{\"state\":\"enabled\"}' --headers 'Content-Type=application/json'" -ForegroundColor Yellow
  Write-Host ""
}

Write-Step "Completed."
