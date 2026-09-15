[CmdletBinding()]
param(
    [ValidateSet('positive', 'negative')]
    [ValidateCount(1, 2)]
    [string[]]$Scenarios = @('positive', 'negative'),
    [ValidateRange(5, 60)][int]$TimeoutMinutes = 30
)

$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'

foreach ($requiredPath in @(
    $applicationStatePath,
    $conditionalAccessStatePath,
    $entraStatePath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

$application = Get-Content -LiteralPath $applicationStatePath -Raw | ConvertFrom-Json
$conditionalAccess = Get-Content -LiteralPath $conditionalAccessStatePath -Raw | ConvertFrom-Json
$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
if ($conditionalAccess.policyState -ne 'enabledForReportingButNotEnforced' -or
    $conditionalAccess.applicationId -ne $application.appId -or
    $conditionalAccess.groupId -ne $entra.groupId -or
    $conditionalAccess.tenantId -ne $application.tenantId) {
    throw 'Conditional Access state does not match the isolated lab.'
}

$pendingScenarios = [ordered]@{}
foreach ($scenario in $Scenarios) {
    $pendingPath = Join-Path $stateDirectory "auth-strength-$scenario-pending.json"
    if (-not (Test-Path -LiteralPath $pendingPath)) {
        throw "Pending '$scenario' evidence state does not exist at '$pendingPath'."
    }
    $pending = Get-Content -LiteralPath $pendingPath -Raw | ConvertFrom-Json
    if ($pending.applicationId -ne $application.appId -or
        $pending.browserConclusion -ne 'passed' -or
        $pending.policyId -ne $conditionalAccess.policyId -or
        $pending.scenario -ne $scenario -or
        $pending.tenantId -ne $application.tenantId -or
        $pending.testUserId -ne $entra.testUserId -or
        $pending.testUserUpn -cne $entra.testUserUpn -or
        $pending.proofSetId -notmatch '^[a-f0-9]{64}$' -or
        [guid]::Parse($pending.correlationId) -eq [guid]::Empty) {
        throw "Pending '$scenario' evidence state does not match the isolated lab."
    }
    $pendingScenarios[$scenario] = $pending
}

$requiredScopes = @('AuditLog.Read.All', 'Policy.Read.All')
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
$context = Get-MgContext
$missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
if (-not $context -or
    $context.TenantId -ne $application.tenantId -or
    $missingScopes.Count -ne 0) {
    throw "Microsoft Graph authorization is missing scopes: $($missingScopes -join ', ')."
}

$remainingScenarios = [Collections.Generic.HashSet[string]]::new(
    [string[]]@($pendingScenarios.Keys)
)
$lastExpectedError = @{}
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
do {
    $exportAvailable = $true
    try {
        & (Join-Path $PSScriptRoot 'Export-CbaSignInEvidence.ps1') `
            -TenantId $application.tenantId `
            -LookbackHours 2
    } catch {
        $isExpectedIngestionDelay = (
            $_.Exception.Message -match '^No sign-in records were returned' -or
            $_.Exception.Message -match 'configured HttpClient.Timeout'
        )
        if (-not $isExpectedIngestionDelay) {
            throw
        }
        $exportAvailable = $false
        foreach ($scenario in @($remainingScenarios)) {
            $lastExpectedError[$scenario] = $_.Exception.Message
        }
    }

    if ($exportAvailable) {
        foreach ($scenario in @($remainingScenarios)) {
            $pending = $pendingScenarios[$scenario]
            try {
                & (Join-Path $PSScriptRoot 'Assert-CbaSignInEvidence.ps1') `
                    -Scenario $scenario `
                    -Since ([DateTimeOffset]::Parse($pending.since)) `
                    -CorrelationId ([guid]::Parse($pending.correlationId)) `
                    -ProofSetId $pending.proofSetId
                $remainingScenarios.Remove($scenario) | Out-Null
            } catch {
                if ($_.Exception.Message -notmatch '^No (recent target-application|correlated)') {
                    throw
                }
                $lastExpectedError[$scenario] = $_.Exception.Message
            }
        }
    }

    if ($remainingScenarios.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Write-Host (
            "Waiting for Entra sign-in evidence: " +
            "$(@($remainingScenarios) -join ', ')."
        )
        Start-Sleep -Seconds 15
    }
} while ($remainingScenarios.Count -gt 0 -and (Get-Date) -lt $deadline)

if ($remainingScenarios.Count -gt 0) {
    $details = @($remainingScenarios | ForEach-Object {
        "${_}: $($lastExpectedError[$_])"
    }) -join ' | '
    throw "Entra sign-in evidence exceeded the $TimeoutMinutes-minute bound. $details"
}

Write-Host "Validated Entra CBA sign-in evidence: $($Scenarios -join ', ')."
