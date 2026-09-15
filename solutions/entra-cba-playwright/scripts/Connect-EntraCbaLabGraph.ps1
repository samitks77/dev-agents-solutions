[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId
)

$ErrorActionPreference = 'Stop'

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
$requiredScopes = @(
    'Application.Read.All',
    'AuditLog.Read.All',
    'Group.ReadWrite.All',
    'Policy.Read.All',
    'Policy.ReadWrite.AuthenticationMethod',
    'Policy.ReadWrite.ConditionalAccess',
    'PublicKeyInfrastructure.ReadWrite.All',
    'User.ReadWrite.All'
)
Connect-MgGraph `
    -TenantId $TenantId `
    -Scopes $requiredScopes `
    -ContextScope CurrentUser `
    -ClientTimeout 600 `
    -NoWelcome

$context = Get-MgContext
$missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
if (-not $context -or $context.TenantId -ne $TenantId -or $missingScopes.Count -ne 0) {
    throw 'The reusable Microsoft Graph context does not contain every required lab scope.'
}

Write-Host "Reusable Microsoft Graph authorization established for tenant '$TenantId'."
