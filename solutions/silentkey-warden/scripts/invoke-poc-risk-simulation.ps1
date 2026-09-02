<#
.SYNOPSIS
Provisions the POC service principals and drives the five risk simulation scenarios end to end.

.DESCRIPTION
Automates what the POC guide walks through by hand, so a demo takes minutes instead of an hour
and produces identical results every time.

Scenarios executed (matching docs/workload-identity-poc-guide.html):
  A  POC-Test-A-AdminConfirm    Admin confirms compromised            -> D2
  B  POC-Test-B-BackdoorCred    Second client secret added            -> D1
  C  POC-Test-C-FabricAccess    First-time resource access            -> D4
  D  POC-Test-D-BurstSignIn     Burst across many resources           -> D3
  E  (reuses the above)         Conditional Access block              -> D5

What it does per identity:
1) Creates an app registration and its service principal.
2) Creates a short-lived client secret.
3) Generates a real sign-in so the identity has token issuance telemetry.
4) Executes the scenario-specific action.
5) Confirms the service principal compromised via the Identity Protection Graph API.

SAFETY
- Run this in a TEST or DEMO tenant. It creates real identities and raises real risk events.
- Secrets are held in memory and printed once. They are never written to disk. Do not paste
  them into tickets, chats, or shared documents.
- Secrets default to a 7 day lifetime.
- ./remove-poc-resources.ps1 reverses everything this script creates.

Permissions required:
- Application.ReadWrite.All, IdentityRiskyServicePrincipal.ReadWrite.All
- Global Administrator or (Application Administrator + Security Administrator)
- Microsoft Entra Workload Identities Premium license

.EXAMPLE
./invoke-poc-risk-simulation.ps1 -WhatIf

.EXAMPLE
./invoke-poc-risk-simulation.ps1 -Scenarios A,B -Force

.EXAMPLE
./invoke-poc-risk-simulation.ps1 -Scenarios A,B,C,D -SecretLifetimeDays 3
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateSet("A", "B", "C", "D")]
  [string[]]$Scenarios = @("A", "B", "C", "D"),

  [Parameter(Mandatory = $false)]
  [string]$NamePrefix = "POC-Test",

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 30)]
  [int]$SecretLifetimeDays = 7,

  # Creates identities and generates sign-ins, but does not raise risk events.
  [switch]$SkipConfirmCompromised,

  # Skips the interactive confirmation prompt.
  [switch]$Force,

  [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "[$(Get-Date -Format o)] $Message" -ForegroundColor Cyan
}

function Write-Detail {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Host "    $Message" -ForegroundColor DarkGray
}

$scenarioCatalog = @{
  "A" = @{ Suffix = "AdminConfirm";  Purpose = "Admin confirms compromised";     Detection = "D2" }
  "B" = @{ Suffix = "BackdoorCred";  Purpose = "Suspicious credential addition"; Detection = "D1" }
  "C" = @{ Suffix = "FabricAccess";  Purpose = "First-time resource access";     Detection = "D4" }
  "D" = @{ Suffix = "BurstSignIn";   Purpose = "Multi-resource burst sign-in";   Detection = "D3" }
}

$burstScopes = @(
  "https://graph.microsoft.com/.default",
  "https://management.azure.com/.default",
  "https://vault.azure.net/.default",
  "https://storage.azure.com/.default",
  "https://database.windows.net/.default",
  "https://analysis.windows.net/powerbi/api/.default",
  "https://api.fabric.microsoft.com/.default"
)

Write-Step "Step 1/5 - Verifying context (what: tenant and tooling check, why: this creates real identities in a real tenant)."
az version --output none
$account = az account show --output json | ConvertFrom-Json
$tenantId = $account.tenantId

Write-Host ""
Write-Host "  Tenant     : $tenantId"
Write-Host "  Signed in  : $($account.user.name)"
Write-Host "  Scenarios  : $($Scenarios -join ', ')"
Write-Host "  Secret life: $SecretLifetimeDays days"
Write-Host ""

if ($WhatIf) {
  Write-Step "WhatIf - the following would be created, then removed by remove-poc-resources.ps1:"
  foreach ($key in $Scenarios) {
    $s = $scenarioCatalog[$key]
    Write-Host "  $NamePrefix-$key-$($s.Suffix)  ->  $($s.Purpose)  ->  feeds $($s.Detection)"
  }
  return
}

if (-not $Force) {
  Write-Host "This creates real app registrations and raises real risk events in tenant $tenantId." -ForegroundColor Yellow
  $answer = Read-Host "Type the word 'simulate' to continue"
  if ($answer -ne "simulate") {
    Write-Host "Aborted. Nothing was created." -ForegroundColor Yellow
    return
  }
}

function New-PocIdentity {
  param(
    [Parameter(Mandatory = $true)][string]$DisplayName,
    [Parameter(Mandatory = $true)][int]$LifetimeDays
  )

  Write-Detail "Creating app registration $DisplayName"
  $app = az ad app create --display-name $DisplayName --sign-in-audience AzureADMyOrg --output json | ConvertFrom-Json

  Write-Detail "Creating service principal"
  $sp = az ad sp create --id $app.appId --output json | ConvertFrom-Json

  $endDate = (Get-Date).AddDays($LifetimeDays).ToString("yyyy-MM-dd")
  Write-Detail "Creating client secret (expires $endDate)"
  $cred = az ad app credential reset --id $app.appId --display-name "POC-Secret" --end-date $endDate --append --output json | ConvertFrom-Json

  return [pscustomobject]@{
    DisplayName = $DisplayName
    AppId       = $app.appId
    AppObjectId = $app.id
    SpObjectId  = $sp.id
    Secret      = $cred.password
  }
}

function Invoke-PocSignIn {
  param(
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $true)][string]$Scope
  )

  $body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = $Scope
  }

  try {
    $null = Invoke-RestMethod `
      -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
      -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
    return $true
  }
  catch {
    return $false
  }
}

function Confirm-PocCompromised {
  param([Parameter(Mandatory = $true)][string]$ServicePrincipalObjectId)

  $payload = @{ servicePrincipalIds = @($ServicePrincipalObjectId) } | ConvertTo-Json -Compress
  $tempFile = New-TemporaryFile
  try {
    Set-Content -Path $tempFile -Value $payload -Encoding utf8
    az rest `
      --method post `
      --url "https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals/confirmCompromised" `
      --body "@$tempFile" `
      --headers "Content-Type=application/json" `
      --output none
    return $true
  }
  catch {
    Write-Host "    Could not confirm compromised. Check IdentityRiskyServicePrincipal.ReadWrite.All consent." -ForegroundColor Red
    return $false
  }
  finally {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
  }
}

Write-Step "Step 2/5 - Provisioning identities (what: app registration + SP + secret per scenario, why: each scenario needs its own identity so they appear separately in the risk blade)."
$identities = @{}
foreach ($key in $Scenarios) {
  $suffix = $scenarioCatalog[$key].Suffix
  $displayName = "$NamePrefix-$key-$suffix"
  Write-Host "  [$key] $displayName"
  $identities[$key] = New-PocIdentity -DisplayName $displayName -LifetimeDays $SecretLifetimeDays
}

Write-Step "Waiting 30 seconds for directory replication (what: propagation delay, why: a brand new SP cannot authenticate immediately)."
Start-Sleep -Seconds 30

Write-Step "Step 3/5 - Generating baseline sign-ins (what: one token request per identity, why: an identity with no sign-in history produces no telemetry to detect on)."
foreach ($key in $Scenarios) {
  $identity = $identities[$key]
  $ok = Invoke-PocSignIn -TenantId $tenantId -ClientId $identity.AppId -ClientSecret $identity.Secret -Scope "https://graph.microsoft.com/.default"
  $status = if ($ok) { "OK" } else { "FAILED (retry in a minute, replication can lag)" }
  Write-Host "  [$key] baseline sign-in: $status"
}

Write-Step "Step 4/5 - Executing scenario-specific actions (what: the actual simulated attack behaviour, why: this is what each detection is written to catch)."

if ($Scenarios -contains "B") {
  Write-Host "  [B] Adding a second 'backdoor-secret' credential (MITRE T1098.001) -> feeds D1"
  $identityB = $identities["B"]
  $endDate = (Get-Date).AddDays($SecretLifetimeDays).ToString("yyyy-MM-dd")
  $null = az ad app credential reset --id $identityB.AppId --display-name "backdoor-secret" --end-date $endDate --append --output none
  Write-Detail "App now holds two credentials. Audit log entry appears in 15-20 minutes."
}

if ($Scenarios -contains "C") {
  Write-Host "  [C] Requesting a Power BI / Fabric token for the first time -> feeds D4"
  $identityC = $identities["C"]
  $ok = Invoke-PocSignIn -TenantId $tenantId -ClientId $identityC.AppId -ClientSecret $identityC.Secret -Scope "https://analysis.windows.net/powerbi/api/.default"
  if ($ok) {
    Write-Detail "Fabric token issued. The resource pivot is now visible in sign-in logs."
  }
  else {
    Write-Detail "Token request failed - expected unless Power BI Service API permission was granted. The failed attempt is still logged."
  }
}

if ($Scenarios -contains "D") {
  Write-Host "  [D] Bursting across $($burstScopes.Count) distinct resources -> feeds D3"
  $identityD = $identities["D"]
  foreach ($scope in $burstScopes) {
    $ok = Invoke-PocSignIn -TenantId $tenantId -ClientId $identityD.AppId -ClientSecret $identityD.Secret -Scope $scope
    $status = if ($ok) { "OK  " } else { "FAIL" }
    Write-Detail "$status $scope"
    Start-Sleep -Seconds 1
  }
  Write-Detail "Burst complete. Failures are expected where no API permission was granted; the sign-in attempt is still recorded."
}

if (-not $SkipConfirmCompromised) {
  Write-Step "Step 5/5 - Confirming each identity compromised (what: Identity Protection admin assertion, why: simulates the SOC response that produces a High risk detection)."
  foreach ($key in $Scenarios) {
    $identity = $identities[$key]
    $ok = Confirm-PocCompromised -ServicePrincipalObjectId $identity.SpObjectId
    $status = if ($ok) { "confirmed compromised (High)" } else { "FAILED" }
    Write-Host "  [$key] $($identity.DisplayName): $status"
  }
}
else {
  Write-Step "Step 5/5 - Skipped confirmCompromised (-SkipConfirmCompromised). Identities exist with sign-in telemetry but no risk events."
}

Write-Host ""
Write-Host "==================== SIMULATION SUMMARY ====================" -ForegroundColor Green
foreach ($key in $Scenarios) {
  $identity = $identities[$key]
  $meta = $scenarioCatalog[$key]
  Write-Host ""
  Write-Host "  Scenario $key - $($meta.Purpose)  (feeds $($meta.Detection))"
  Write-Host "    Display name        : $($identity.DisplayName)"
  Write-Host "    Application (client): $($identity.AppId)"
  Write-Host "    SP object id        : $($identity.SpObjectId)"
}
Write-Host ""
Write-Host "  Client secrets are intentionally NOT printed or persisted." -ForegroundColor Yellow
Write-Host "  They live only in this process and expire in $SecretLifetimeDays days." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "What to check next:" -ForegroundColor Yellow
Write-Host "  Now          : Protection > Identity Protection > Risky workload identities" -ForegroundColor Yellow
Write-Host "  15-30 min    : Identity > Monitoring > Sign-in logs > Service principal sign-ins" -ForegroundColor Yellow
Write-Host "  15-30 min    : detections D2, D3, D4 return rows in Log Analytics" -ForegroundColor Yellow
Write-Host "  15-20 min    : detection D1 returns the backdoor credential addition" -ForegroundColor Yellow
Write-Host "  When done    : ./remove-poc-resources.ps1" -ForegroundColor Yellow
Write-Host ""

Write-Step "Simulation completed."
