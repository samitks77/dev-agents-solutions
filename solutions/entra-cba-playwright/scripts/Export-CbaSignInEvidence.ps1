[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateRange(1, 24)][int]$LookbackHours = 2,
    [switch]$Connect
)

$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$evidencePath = Join-Path $stateDirectory 'sign-in-evidence.json'

foreach ($requiredPath in @($applicationStatePath, $entraStatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

$application = Get-Content -LiteralPath $applicationStatePath -Raw | ConvertFrom-Json
$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
if ($application.tenantId -ne $TenantId -or $entra.tenantId -ne $TenantId) {
    throw 'Local application or Entra state belongs to a different tenant.'
}

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force

$requiredScopes = @('AuditLog.Read.All')
$context = Get-MgContext
$missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
$hasRequiredContext = $context -and $context.TenantId -eq $TenantId -and $missingScopes.Count -eq 0

if (-not $hasRequiredContext) {
    if (-not $Connect) {
        throw "No reusable Microsoft Graph context for tenant '$TenantId' has scopes: $($requiredScopes -join ', '). Rerun with -Connect to authorize once in the system browser."
    }

    Connect-MgGraph `
        -TenantId $TenantId `
        -Scopes $requiredScopes `
        -ContextScope CurrentUser `
        -ClientTimeout 600 `
        -NoWelcome
    $context = Get-MgContext
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
}

if (-not $context -or $context.TenantId -ne $TenantId -or $missingScopes.Count -ne 0) {
    throw "Microsoft Graph authorization for '$($requiredScopes -join ', ')' in tenant '$TenantId' is required."
}

$startTime = [DateTime]::UtcNow.AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = [Uri]::EscapeDataString(
    "userId eq '$($entra.testUserId)' and createdDateTime ge $startTime"
)
$uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$filter&`$orderby=createdDateTime desc&`$top=100"

$entries = [Collections.Generic.List[object]]::new()
while ($uri) {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($entry in @($response.value)) {
        $entries.Add($entry)
    }
    $uri = $response.'@odata.nextLink'
}

if ($entries.Count -eq 0) {
    throw "No sign-in records were returned for '$($entra.testUserUpn)' in the last $LookbackHours hour(s)."
}

$sanitizedEntries = @(foreach ($entry in $entries) {
    [ordered]@{
        appDisplayName = $entry.appDisplayName
        appId = $entry.appId
        appliedConditionalAccessPolicies = @(
            $entry.appliedConditionalAccessPolicies | ForEach-Object {
                [ordered]@{
                    displayName = $_.displayName
                    enforcedGrantControls = @($_.enforcedGrantControls)
                    id = $_.id
                    result = $_.result
                }
            }
        )
        authenticationDetails = @(
            $entry.authenticationDetails | ForEach-Object {
                [ordered]@{
                    authenticationMethod = $_.authenticationMethod
                    authenticationMethodDetail = $_.authenticationMethodDetail
                    authenticationStepDateTime = $_.authenticationStepDateTime
                    authenticationStepRequirement = $_.authenticationStepRequirement
                    detail = $_.authenticationStepResultDetail
                    succeeded = $_.succeeded
                }
            }
        )
        authenticationProcessingDetails = @(
            $entry.authenticationProcessingDetails | ForEach-Object {
                [ordered]@{
                    key = $_.key
                    value = $_.value
                }
            }
        )
        authenticationRequirement = $entry.authenticationRequirement
        conditionalAccessStatus = $entry.conditionalAccessStatus
        correlationId = $entry.correlationId
        createdDateTime = $entry.createdDateTime
        id = $entry.id
        isInteractive = $entry.isInteractive
        resourceDisplayName = $entry.resourceDisplayName
        status = [ordered]@{
            additionalDetails = $entry.status.additionalDetails
            errorCode = $entry.status.errorCode
            failureReason = $entry.status.failureReason
        }
        userPrincipalName = $entry.userPrincipalName
    }
})

$evidence = [ordered]@{
    applicationId = $application.appId
    exportedAt = (Get-Date).ToString('o')
    lookbackHours = $LookbackHours
    recordCount = $sanitizedEntries.Count
    records = @($sanitizedEntries)
    tenantId = $TenantId
    testUserId = $entra.testUserId
    testUserUpn = $entra.testUserUpn
}
$evidence | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM

Write-Host "Exported $($sanitizedEntries.Count) sanitized sign-in record(s) to '$evidencePath'."
