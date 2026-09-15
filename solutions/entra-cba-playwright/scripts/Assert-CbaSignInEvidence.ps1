[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('positive', 'negative')]
    [string]$Scenario,
    [Parameter(Mandatory)]
    [DateTimeOffset]$Since,
    [Parameter(Mandatory)]
    [guid]$CorrelationId,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ProofSetId
)

$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$conditionalAccessIsolationStatePath = Join-Path `
    $stateDirectory `
    'conditional-access-isolation.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$evidencePath = Join-Path $stateDirectory 'sign-in-evidence.json'
$receiptPath = Join-Path $stateDirectory "auth-strength-$Scenario.json"

foreach ($requiredPath in @(
    $applicationStatePath,
    $conditionalAccessStatePath,
    $entraStatePath,
    $evidencePath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

$application = Get-Content -LiteralPath $applicationStatePath -Raw | ConvertFrom-Json
$conditionalAccess = Get-Content -LiteralPath $conditionalAccessStatePath -Raw | ConvertFrom-Json
$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
$evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
if ($conditionalAccess.policyState -notin @('enabled', 'enabledForReportingButNotEnforced') -or
    $conditionalAccess.applicationId -ne $application.appId -or
    $conditionalAccess.groupId -ne $entra.groupId -or
    $evidence.applicationId -ne $application.appId -or
    $evidence.testUserId -ne $entra.testUserId) {
    throw 'Conditional Access or sign-in evidence state does not match the isolated lab.'
}
$isolatedPolicyIds = @()
if (-not (Test-Path -LiteralPath $conditionalAccessIsolationStatePath)) {
    throw 'Authentication-strength evidence requires a restored isolation receipt.'
}
$isolation = Get-Content `
    -LiteralPath $conditionalAccessIsolationStatePath `
    -Raw | ConvertFrom-Json
if ($isolation.schemaVersion -ne 3 -or
    $isolation.status -ne 'restored' -or
    $isolation.tenantId -ne $application.tenantId -or
    $isolation.applicationId -ne $application.appId -or
    $isolation.proofSetId -cne $ProofSetId) {
    throw 'Authentication-strength evidence belongs to a different proof set.'
}
if ($Scenario -eq 'negative') {
    $isolatedPolicyIds = @($isolation.policies.id | Sort-Object -Unique)
    $appliedPolicyIds = @($isolation.appliedPolicyIds | Sort-Object -Unique)
    $restoredPolicyIds = @($isolation.restoredPolicyIds | Sort-Object -Unique)
    if ($isolatedPolicyIds.Count -eq 0 -or
        (Compare-Object $isolatedPolicyIds $appliedPolicyIds) -or
        (Compare-Object $isolatedPolicyIds $restoredPolicyIds)) {
        throw 'Negative evidence does not have a complete restored isolation receipt.'
    }
}

$expectedCorrelationId = $CorrelationId.ToString()
if ($CorrelationId -eq [guid]::Empty) {
    throw 'The expected sign-in correlation ID cannot be empty.'
}
$correlationRecords = @($evidence.records | Where-Object {
    $_.correlationId -eq $expectedCorrelationId -and
    [DateTimeOffset]::Parse($_.createdDateTime) -ge $Since.ToUniversalTime().AddMinutes(-1)
})
$records = @($correlationRecords | Where-Object {
    $_.appId -eq $application.appId -and
    $_.userPrincipalName -eq $entra.testUserUpn
})
if ($records.Count -eq 0) {
    throw 'No recent target-application sign-in record was found for the dedicated test user.'
}

$matchedRecord = $null
$matchedCorrelationRecords = @()
foreach ($record in $records) {
    $appliedPolicy = @($record.appliedConditionalAccessPolicies | Where-Object {
        $_.id -eq $conditionalAccess.policyId
    })
    if ($Scenario -eq 'negative' -and $appliedPolicy.Count -ne 1) {
        continue
    }

    $policyResult = if ($appliedPolicy.Count -eq 1) {
        [string]$appliedPolicy[0].result
    } else {
        $null
    }
    $statusCode = [int64]$record.status.errorCode
    $isolatedPoliciesNotApplied = if ($Scenario -eq 'negative') {
        $allExpectedPoliciesNotApplied = $true
        foreach ($policyId in $isolatedPolicyIds) {
            $isolatedMatches = @(
                $record.appliedConditionalAccessPolicies |
                    Where-Object { $_.id -eq $policyId }
            )
            if ($isolatedMatches.Count -ne 1 -or
                $isolatedMatches[0].result -ne 'notApplied') {
                $allExpectedPoliciesNotApplied = $false
                break
            }
        }
        $unexpectedPolicyFailures = @(
            $record.appliedConditionalAccessPolicies |
                Where-Object {
                    $_.result -eq 'failure' -and
                    $_.id -ne $conditionalAccess.policyId
                }
        )
        $allExpectedPoliciesNotApplied -and
            $unexpectedPolicyFailures.Count -eq 0
    } else {
        $true
    }
    $expectedOutcome = if ($Scenario -eq 'positive') {
        $correlatedPolicySuccess = @(
            $correlationRecords | Where-Object {
                @(
                    $_.appliedConditionalAccessPolicies | Where-Object {
                        $_.id -eq $conditionalAccess.policyId -and
                        $_.result -eq 'success'
                    }
                ).Count -eq 1
            }
        ).Count -gt 0
        $correlatedPolicyFailure = @(
            $correlationRecords.appliedConditionalAccessPolicies | Where-Object {
                $_.id -eq $conditionalAccess.policyId -and
                $_.result -in @('failure', 'reportOnlyFailure')
            }
        ).Count -gt 0
        $statusCode -eq 0 -and
            $correlatedPolicySuccess -and
            -not $correlatedPolicyFailure
    } else {
        $statusCode -eq 500187 -and
        $policyResult -eq 'failure' -and
        $isolatedPoliciesNotApplied -and
        $record.status.failureReason -match (
            'certificate does not meet the criteria required by ' +
            'conditional access authentication strength'
        )
    }
    if (-not $expectedOutcome) {
        continue
    }

    $certificateDetails = @($correlationRecords.authenticationDetails | Where-Object {
        $_.authenticationMethod -match 'certificate'
    })
    $certificateSucceeded = @($certificateDetails | Where-Object {
        $_.authenticationMethod -match 'certificate' -and $_.succeeded -eq $true
    }).Count -gt 0
    $certificateRejected = @($certificateDetails | Where-Object {
        $_.succeeded -eq $false
    }).Count -gt 0
    $certificateAuthenticationLevels = @(
        $correlationRecords.authenticationProcessingDetails |
            Where-Object { $_.key -eq 'User certificate authentication level' } |
            Select-Object -ExpandProperty value -Unique
    )
    $modernPkiStoreUsed = @($correlationRecords.authenticationProcessingDetails | Where-Object {
        $_.key -eq 'Is Legacy Store Used' -and [string]$_.value -eq '0'
    }).Count -gt 0
    $expectedCertificateEvidence = if ($Scenario -eq 'positive') {
        $certificateSucceeded -and
        @($certificateAuthenticationLevels).Count -eq 1 -and
        $certificateAuthenticationLevels[0] -eq 'multiFactorAuthentication'
    } else {
        $certificateRejected -and -not $certificateSucceeded -and
        @($certificateAuthenticationLevels).Count -eq 1 -and
        $certificateAuthenticationLevels[0] -eq 'singleFactorAuthentication'
    }
    if ($expectedCertificateEvidence -and $modernPkiStoreUsed) {
        $matchedRecord = $record
        $matchedCorrelationRecords = $correlationRecords
        $matchedCertificateAuthenticationLevel = $certificateAuthenticationLevels[0]
        $matchedCertificateStepSucceeded = $certificateSucceeded
        break
    }
}

if (-not $matchedRecord) {
    $certificateOutcome = if ($Scenario -eq 'positive') {
        'successful certificate authentication'
    } else {
        'rejected single-factor certificate authentication'
    }
    throw (
        "No correlated '$Scenario' sign-in proves the exact Conditional Access policy, " +
        "$certificateOutcome, and modern PKI-store use."
    )
}

$matchedPolicyResult = if ($Scenario -eq 'positive') {
    'success'
} else {
    @($matchedRecord.appliedConditionalAccessPolicies | Where-Object {
        $_.id -eq $conditionalAccess.policyId
    })[0].result
}
$receipt = [ordered]@{
    applicationId = $application.appId
    authenticationMethod = 'Certificate-based authentication'
    certificateAuthenticationLevel = $matchedCertificateAuthenticationLevel
    certificateStepSucceeded = $matchedCertificateStepSucceeded
    correlationId = $expectedCorrelationId
    errorCode = [int64]$matchedRecord.status.errorCode
    evidenceRecordIds = @($matchedCorrelationRecords.id)
    modernPkiStoreUsed = $true
    isolatedManagedPolicyIds = @($isolatedPolicyIds)
    policyDisplayName = $conditionalAccess.policyDisplayName
    policyId = $conditionalAccess.policyId
    policyResult = $matchedPolicyResult
    proofSetId = $ProofSetId
    scenario = $Scenario
    signInCreatedDateTime = $matchedRecord.createdDateTime
    validatedAt = (Get-Date).ToString('o')
}
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8NoBOM

Write-Host (
    "Validated '$Scenario' CBA evidence for policy '$($conditionalAccess.policyDisplayName)' " +
    "with correlation '$expectedCorrelationId'."
)
