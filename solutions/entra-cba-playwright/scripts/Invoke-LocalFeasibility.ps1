[CmdletBinding()]
param(
    [ValidateRange(1, 20)][int]$Repeat = 1,
    [switch]$AuthenticationStrengthNegative,
    [switch]$AuthenticationStrengthPositive,
    [switch]$DeferSignInEvidence,
    [switch]$Headed,
    [string]$ProofSetId,
    [switch]$ShowProof,
    [switch]$WrongOrigin,
    [switch]$ReuseSession
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

if ($ShowProof -and -not $Headed) {
    throw 'ShowProof requires Headed so the authenticated page can remain visible.'
}
if ($DeferSignInEvidence -and
    -not ($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive)) {
    throw 'DeferSignInEvidence requires an authentication-strength scenario.'
}
if (($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive) -and
    $ProofSetId -notmatch '^[a-f0-9]{64}$') {
    throw 'Authentication-strength scenarios require the exact cloud proof-set ID.'
}
if ($ProofSetId -and $ProofSetId -notmatch '^[a-f0-9]{64}$') {
    throw 'ProofSetId must be a lowercase SHA-256 value.'
}

$selectedScenarios = @(
    if ($AuthenticationStrengthNegative) { 'AuthenticationStrengthNegative' }
    if ($AuthenticationStrengthPositive) { 'AuthenticationStrengthPositive' }
    if ($ReuseSession) { 'ReuseSession' }
    if ($WrongOrigin) { 'WrongOrigin' }
)
if ($selectedScenarios.Count -gt 1) {
    throw "Select only one scenario: $($selectedScenarios -join ', ')."
}
if ($ShowProof -and ($WrongOrigin -or $ReuseSession -or $AuthenticationStrengthNegative)) {
    throw 'ShowProof is supported only for positive direct-authentication scenarios.'
}

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$pkiStatePath = Join-Path $stateDirectory 'pki.json'

function Write-JsonAtomically {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Collections.IDictionary]$Value
    )

    $operationId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$Path.$operationId.tmp"
    $backupPath = "$Path.$operationId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($Value | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
        } else {
            [IO.File]::Move($temporaryPath, $Path)
        }
    } finally {
        foreach ($cleanupPath in @($temporaryPath, $backupPath)) {
            if (Test-Path -LiteralPath $cleanupPath) {
                Remove-Item -LiteralPath $cleanupPath -Force
            }
        }
    }
}

foreach ($requiredPath in @($applicationStatePath, $entraStatePath, $pkiStatePath)) {
    if (-not (Test-Path $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

$application = Get-Content $applicationStatePath -Raw | ConvertFrom-Json
$entra = Get-Content $entraStatePath -Raw | ConvertFrom-Json
$pki = Get-Content $pkiStatePath -Raw | ConvertFrom-Json
if ($application.tenantId -ne $entra.tenantId -or $application.testUsername -ne $entra.testUserUpn) {
    throw 'Application and Entra state identify different test users or tenants.'
}
$certificateName = if ($AuthenticationStrengthNegative) {
    'cba-playwright-test-sfa'
} else {
    'cba-playwright-test-mfa'
}
$certificate = @($pki.certificates | Where-Object { $_.name -eq $certificateName })
if ($certificate.Count -ne 1) {
    throw "Expected exactly one '$certificateName' certificate in PKI state."
}

if ($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive) {
    if (-not (Test-Path -LiteralPath $conditionalAccessStatePath)) {
        throw "Conditional Access state not found at '$conditionalAccessStatePath'."
    }
    $conditionalAccess = Get-Content -LiteralPath $conditionalAccessStatePath -Raw | ConvertFrom-Json
    if ($conditionalAccess.policyState -ne 'enabled' -or
        $conditionalAccess.tenantId -ne $entra.tenantId -or
        $conditionalAccess.groupId -ne $entra.groupId -or
        $conditionalAccess.applicationId -ne $application.appId -or
        $conditionalAccess.authenticationStrengthDisplayName -ne 'Phishing-resistant MFA') {
        throw 'Conditional Access state does not prove an enabled, exactly scoped phishing-resistant MFA policy.'
    }
}

$securePassphrase = Import-Clixml -Path $pki.pfxPassphrasePath
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassphrase)
try {
    $env:CBA_PFX_PASSPHRASE = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}

$env:CBA_APP_CLIENT_ID = $application.appId
$env:CBA_APP_URL = $application.appUrl
$env:CBA_CERTAUTH_ORIGIN = 'https://certauth.login.microsoftonline.com'
$env:CBA_PFX_PATH = $certificate[0].pfxPath
$env:CBA_SHOW_PROOF = if ($ShowProof) { 'true' } else { 'false' }
$env:CBA_TENANT_ID = $application.tenantId
$env:CBA_TEST_OBJECT_ID = $entra.testUserId
$env:CBA_TEST_USERNAME = $application.testUsername
$correlationId = if ($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive) {
    [guid]::NewGuid().ToString()
} else {
    $null
}
if ($correlationId) {
    $env:CBA_SIGN_IN_CORRELATION_ID = $correlationId
}
$env:RUN_AUTH_STRENGTH_TESTS = if ($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive) {
    'true'
} else {
    'false'
}
$env:RUN_NEGATIVE_CBA_TESTS = if ($WrongOrigin) { 'true' } else { 'false' }

$project = if ($AuthenticationStrengthNegative) {
    'cba-auth-strength-negative'
} elseif ($AuthenticationStrengthPositive) {
    'cba-auth-strength-positive'
} elseif ($WrongOrigin) {
    'cba-wrong-origin'
} elseif ($ReuseSession) {
    'authenticated-session'
} else {
    'cba-feasibility'
}
$authenticationStrengthScenario = if ($AuthenticationStrengthNegative) {
    'negative'
} elseif ($AuthenticationStrengthPositive) {
    'positive'
} else {
    $null
}

$arguments = @('playwright', 'test', "--project=$project")
if ($Headed) {
    $arguments += '--headed'
}

try {
    $scenarioStartedAt = [DateTimeOffset]::Now
    $pendingEvidence = $null
    $pendingEvidencePath = $null
    if ($DeferSignInEvidence) {
        $pendingEvidencePath = Join-Path `
            $stateDirectory `
            "auth-strength-$authenticationStrengthScenario-pending.json"
        $pendingEvidence = [ordered]@{
            applicationId = $application.appId
            browserCompletedAt = $null
            browserConclusion = 'started'
            correlationId = $correlationId
            policyId = $conditionalAccess.policyId
            proofSetId = $ProofSetId
            scenario = $authenticationStrengthScenario
            since = $scenarioStartedAt.ToString('o')
            tenantId = $application.tenantId
            testUserId = $entra.testUserId
            testUserUpn = $entra.testUserUpn
        }
        Write-JsonAtomically -Path $pendingEvidencePath -Value $pendingEvidence
    }

    Push-Location $labRoot
    try {
        for ($run = 1; $run -le $Repeat; $run++) {
            Write-Host "Playwright run $run of $Repeat using project '$project'."
            & npx @arguments
            if ($LASTEXITCODE -ne 0) {
                throw "Playwright run $run failed with exit code $LASTEXITCODE."
            }
        }
    } finally {
        Pop-Location
    }

    if (-not ($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive)) {
        $identityMaterial = [ordered]@{
            appUrl = $application.appUrl
            objectId = $entra.testUserId
            tenantId = $application.tenantId
            username = $entra.testUserUpn
        } | ConvertTo-Json -Compress
        $identitySha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($identityMaterial)
            )
        ).ToLowerInvariant()
        $testFilePath = Join-Path $labRoot "tests\$project.spec.ts"
        $sourceCommit = (& git -C $labRoot rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0 -or
            $sourceCommit -notmatch '^[a-f0-9]{40}$' -or
            -not (Test-Path -LiteralPath $testFilePath -PathType Leaf)) {
            throw 'Unable to bind local Playwright evidence to the exact source revision.'
        }
        $receiptDefinition = if ($WrongOrigin) {
            @{
                assertions = @(
                    'unapproved-origin-rejected',
                    'no-certificate-detected'
                )
                fileName = 'wrong-origin-control.json'
                scenario = 'wrong-origin'
            }
        } elseif ($ReuseSession) {
            @{
                assertions = @(
                    'exact-identity-reused',
                    'certificate-authentication-request-count-zero'
                )
                fileName = 'session-reuse.json'
                scenario = 'session-reuse'
            }
        } elseif ($Headed) {
            @{
                assertions = @('exact-identity-rendered-in-headed-chromium')
                fileName = 'headed-feasibility.json'
                scenario = 'headed-feasibility'
            }
        } elseif ($Repeat -gt 1) {
            @{
                assertions = @('all-independent-headless-runs-passed')
                fileName = 'headless-reliability.json'
                scenario = 'headless-reliability'
            }
        } else {
            @{
                assertions = @('exact-identity-rendered')
                fileName = 'local-feasibility.json'
                scenario = 'local-feasibility'
            }
        }
        $localReceipt = [ordered]@{
            assertions = @($receiptDefinition.assertions)
            conclusion = 'passed'
            headed = [bool]$Headed
            identitySha256 = $identitySha256
            project = $project
            proofSetId = $ProofSetId
            repeatRequested = $Repeat
            scenario = $receiptDefinition.scenario
            schemaVersion = 1
            sourceCommit = $sourceCommit
            successfulRuns = $Repeat
            testFileSha256 = (
                Get-FileHash -LiteralPath $testFilePath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            verifiedAt = (Get-Date).ToString('o')
        }
        Write-JsonAtomically `
            -Path (Join-Path $stateDirectory $receiptDefinition.fileName) `
            -Value $localReceipt
    }

    if ($pendingEvidence) {
        $pendingEvidence.browserCompletedAt = (Get-Date).ToString('o')
        $pendingEvidence.browserConclusion = 'passed'
        Write-JsonAtomically -Path $pendingEvidencePath -Value $pendingEvidence
        Write-Host (
            "Deferred '$authenticationStrengthScenario' sign-in evidence for correlation " +
            "'$correlationId' until after policy restoration."
        )
    }

    if (($AuthenticationStrengthNegative -or $AuthenticationStrengthPositive) -and
        -not $DeferSignInEvidence) {
        $evidenceDeadline = (Get-Date).AddMinutes(5)
        $lastEvidenceError = $null
        do {
            try {
                & (Join-Path $PSScriptRoot 'Export-CbaSignInEvidence.ps1') `
                    -TenantId $application.tenantId `
                    -LookbackHours 2
                & (Join-Path $PSScriptRoot 'Assert-CbaSignInEvidence.ps1') `
                    -Scenario $authenticationStrengthScenario `
                    -Since $scenarioStartedAt `
                    -CorrelationId $correlationId `
                    -ProofSetId $ProofSetId
                $lastEvidenceError = $null
                break
            } catch {
                $lastEvidenceError = $_
                if ((Get-Date) -lt $evidenceDeadline) {
                    Start-Sleep -Seconds 15
                }
            }
        } while ((Get-Date) -lt $evidenceDeadline)

        if ($lastEvidenceError) {
            throw "Sign-in evidence validation failed: $($lastEvidenceError.Exception.Message)"
        }
    }
} finally {
    @(
        'CBA_APP_CLIENT_ID',
        'CBA_APP_URL',
        'CBA_CERTAUTH_ORIGIN',
        'CBA_PFX_PASSPHRASE',
        'CBA_PFX_PATH',
        'CBA_SIGN_IN_CORRELATION_ID',
        'CBA_SHOW_PROOF',
        'CBA_TENANT_ID',
        'CBA_TEST_OBJECT_ID',
        'CBA_TEST_USERNAME',
        'RUN_AUTH_STRENGTH_TESTS',
        'RUN_NEGATIVE_CBA_TESTS'
    ) | ForEach-Object {
        Remove-Item "Env:$_" -ErrorAction SilentlyContinue
    }
}
