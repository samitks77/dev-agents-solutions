<#
.SYNOPSIS
Runs post-deployment smoke tests for Guest Permissions bootstrap resources.

.DESCRIPTION
What this script does:
1) Checks each core resource exists and is queryable.
2) Optionally checks the expected Azure Files share.
3) Prints a concise PASS summary.

Why this script exists:
- Verifies baseline platform health before runtime onboarding.
- Provides demo-safe confidence checks for internal/customer walkthroughs.

.EXAMPLE
.\post-deploy-smoke-test.ps1 -ResourceGroupName rg-guest-permissions -ManagedIdentityName mi-guest-permissions -LogAnalyticsWorkspaceName law-guest-permissions -ContainerAppsEnvironmentName cae-guest-permissions -GrafanaName amg-guest-permissions -FileShareName guest-permissions
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$ManagedIdentityName,

  [Parameter(Mandatory = $true)]
  [string]$LogAnalyticsWorkspaceName,

  [Parameter(Mandatory = $true)]
  [string]$ContainerAppsEnvironmentName,

  [Parameter(Mandatory = $true)]
  [string]$GrafanaName,

  [Parameter(Mandatory = $false)]
  [string]$FileShareName = "guest-permissions",

  [Parameter(Mandatory = $false)]
  [string]$StorageAccountName
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

Write-Step "Step 1/6 - Checking managed identity (what: identity exists, why: runtime auth dependency)."
$identity = az identity show --resource-group $ResourceGroupName --name $ManagedIdentityName --output json | ConvertFrom-Json
Write-Host "PASS: Managed identity found. PrincipalId=$($identity.principalId)"

Write-Step "Step 2/6 - Checking Log Analytics workspace (what: telemetry target exists, why: observability dependency)."
$workspace = az monitor log-analytics workspace show --resource-group $ResourceGroupName --workspace-name $LogAnalyticsWorkspaceName --output json | ConvertFrom-Json
Write-Host "PASS: Log Analytics workspace found. CustomerId=$($workspace.customerId)"

Write-Step "Step 3/6 - Checking Container Apps environment (what: runtime host exists, why: job execution dependency)."
$environment = az containerapp env show --resource-group $ResourceGroupName --name $ContainerAppsEnvironmentName --output json | ConvertFrom-Json
Write-Host "PASS: Container Apps environment found. Id=$($environment.id)"

Write-Step "Step 4/6 - Checking Managed Grafana (what: dashboard host exists, why: visualization dependency)."
$grafana = az grafana show --resource-group $ResourceGroupName --name $GrafanaName --output json | ConvertFrom-Json
Write-Host "PASS: Managed Grafana found. Endpoint=$($grafana.properties.endpoint)"

Write-Step "Step 5/6 - Resolving storage account (what: locate persistence account, why: snapshot dependency)."
if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
  $StorageAccountName = az storage account list --resource-group $ResourceGroupName --query "[0].name" --output tsv
}
if ([string]::IsNullOrWhiteSpace($StorageAccountName)) {
  throw "No storage account found in resource group $ResourceGroupName."
}
Write-Host "PASS: Storage account resolved. Name=$StorageAccountName"

Write-Step "Step 6/6 - Checking file share (what: snapshot share exists, why: evidence persistence dependency)."
$share = az storage share-rm show --resource-group $ResourceGroupName --storage-account $StorageAccountName --name $FileShareName --output json | ConvertFrom-Json
Write-Host "PASS: File share found. Name=$($share.name)"

Write-Step "Smoke test completed successfully."
