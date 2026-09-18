[CmdletBinding()]
param(
    [ValidateSet('PublicProof', 'EvidenceReplay', 'FreshRun')]
    [string]$Tier = 'PublicProof',

    [string]$Repository,
    [string]$Ref,
    [string]$WorkflowFile = 'entra-cba-playwright-poc.yml',
    [switch]$ConfirmTenantMutations,
    [string]$InterferingPolicyIdsCsv,
    [switch]$ConfirmExclusiveConditionalAccessWindow,
    [ValidateRange(30, 1800)]
    [int]$PropagationSeconds = 900,
    [ValidateRange(30, 300)]
    [int]$NegativeFinalizationSeconds = 120,
    [ValidateRange(5, 60)]
    [int]$EvidenceTimeoutMinutes = 30,

    [long]$ExpectedRunId,
    [string]$ExpectedHeadSha,
    [guid]$ExpectedPositiveCorrelationId,
    [guid]$ExpectedNegativeCorrelationId
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
# FreshRun invokes scripts that consume dynamic Graph and Azure JSON with optional members.
Set-StrictMode -Version 1.0

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$proofDirectory = Join-Path $labRoot '.artifacts\showcase'
$proofJsonPath = Join-Path $proofDirectory 'e2e-proof.json'

function Write-TierBanner {
    param([Parameter(Mandatory)][string]$Text)

    Write-Host ''
    Write-Host ('=' * 80)
    Write-Host $Text
    Write-Host ('=' * 80)
}

function Assert-ExactE2eProof {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "The verifier did not create '$Path'."
    }
    $proof = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if (
        $proof.overallResult -cne 'PASS' -or
        [int]$proof.summary.total -ne 37 -or
        [int]$proof.summary.passed -ne 37 -or
        [int]$proof.summary.failed -ne 0 -or
        @($proof.checks).Count -ne 37 -or
        @($proof.checks | Where-Object { $_.result -cne 'PASS' }).Count -ne 0
    ) {
        throw (
            'Verification is not an exact 37/37 pass: ' +
            "result=$($proof.overallResult), total=$($proof.summary.total), " +
            "passed=$($proof.summary.passed), failed=$($proof.summary.failed)."
        )
    }
    return $proof
}

function Invoke-E2eProofReplay {
    param([hashtable]$Parameters = @{})

    if (Test-Path -LiteralPath $proofJsonPath -PathType Leaf) {
        Remove-Item -LiteralPath $proofJsonPath -Force
    }
    & (Join-Path $PSScriptRoot 'Show-E2eProof.ps1') @Parameters
    return Assert-ExactE2eProof -Path $proofJsonPath
}

function Assert-PublicProof {
    $proofUrl = (
        'https://github.com/samitks77/dev-agents-solutions/releases/download/' +
        'entra-cba-playwright-proof-2026-09-16/entra-cba-proof-public-v2.json'
    )
    $expectedProofSha256 = '9815658f2491dca9f94f2a3a32aa67cdd9797b8850f33863b3555286fee1617f'
    $temporaryProofPath = [IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $proofUrl -OutFile $temporaryProofPath
        $actualProofSha256 = (
            Get-FileHash -LiteralPath $temporaryProofPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualProofSha256 -cne $expectedProofSha256) {
            throw 'The downloaded public proof does not match its pinned SHA-256.'
        }

        $proof = Get-Content -LiteralPath $temporaryProofPath -Raw | ConvertFrom-Json
        if (
            [int]$proof.schemaVersion -ne 2 -or
            $proof.verdict -cne 'PASS' -or
            $proof.source.repository -cne 'samitks77/dev-agents-solutions' -or
            $proof.source.branch -cne 'main' -or
            $proof.source.runtimeTestedCommit -cne '76ee8f37e90a4531c793213998421b6ed94bfdea' -or
            $proof.source.workflowEvent -cne 'workflow_dispatch' -or
            $proof.source.workflowRunLinked -ne $false -or
            [int]$proof.verification.checksTotal -ne 37 -or
            [int]$proof.verification.checksPassed -ne 37 -or
            [int]$proof.verification.checksFailed -ne 0 -or
            $proof.verification.publicWorkflowLogPrivacy -cne 'pass' -or
            [int]$proof.verification.publicWorkflowArtifactsRemaining -ne 0 -or
            [int]$proof.verification.historicalUnsafeWorkflowRunsRemaining -ne 0 -or
            $proof.conditionalAccess.positiveCorrelationValidated -ne $true -or
            $proof.conditionalAccess.positivePolicyResult -cne 'success' -or
            $proof.conditionalAccess.positiveCertificateLevel -cne 'multiFactorAuthentication' -or
            $proof.conditionalAccess.negativeCorrelationValidated -ne $true -or
            $proof.conditionalAccess.negativePolicyResult -cne 'failure' -or
            [int]$proof.conditionalAccess.negativeErrorCode -ne 500187 -or
            $proof.conditionalAccess.negativeCertificateLevel -cne 'singleFactorAuthentication' -or
            $proof.conditionalAccess.restorationStatus -cne 'restored' -or
            $proof.conditionalAccess.finalLabPolicyState -cne 'enabledForReportingButNotEnforced' -or
            $proof.cleanup.transientEvidenceArtifactDeleted -ne $true -or
            $proof.cleanup.aciContainerDeleted -ne $true -or
            $proof.cleanup.githubRunnerDeregistered -ne $true -or
            [int]$proof.cleanup.liveArtifactMatches -ne 0 -or
            [int]$proof.cleanup.liveAciMatches -ne 0 -or
            [int]$proof.cleanup.liveGitHubRunnerMatches -ne 0
        ) {
            throw 'The downloaded public proof does not satisfy the exact published proof contract.'
        }

        $privacyProperties = @($proof.privacy.PSObject.Properties)
        if (
            $privacyProperties.Count -ne 11 -or
            @($privacyProperties | Where-Object { $_.Value -ne $false }).Count -ne 0
        ) {
            throw 'The downloaded public proof does not satisfy the exact privacy contract.'
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryProofPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-ConditionalAccessIsolationStatus {
    param([Parameter(Mandatory)][string]$TenantId)

    $isolationStatePath = Join-Path $stateDirectory 'conditional-access-isolation.json'
    $isolationLockPath = Join-Path $stateDirectory 'conditional-access-isolation.lock'
    try {
        $isolationLockStream = [IO.File]::Open(
            $isolationLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch [IO.IOException] {
        throw 'Another Conditional Access isolation transaction is active.'
    }
    try {
        if (-not (Test-Path -LiteralPath $isolationStatePath -PathType Leaf)) {
            return $null
        }
        $isolationState = Get-Content -LiteralPath $isolationStatePath -Raw |
            ConvertFrom-Json
        if (
            [int]$isolationState.schemaVersion -ne 3 -or
            $isolationState.tenantId -ine $TenantId -or
            $isolationState.status -notin @(
                'prepared',
                'applying',
                'applied',
                'restoring',
                'restored'
            ) -or
            (
                $isolationState.status -ceq 'restored' -and
                -not $isolationState.restoredAt
            )
        ) {
            throw 'Conditional Access isolation state is invalid for this tenant.'
        }
        return [string]$isolationState.status
    }
    finally {
        $isolationLockStream.Dispose()
    }
}

switch ($Tier) {
    'PublicProof' {
        Write-TierBanner @'
TIER A -- PUBLIC PROOF VERIFICATION
No authentication, tenant access, or mutation. This validates local public-template safety plus
the exact hash and pass/privacy contract of the published 37-check proof. It does not rerun CBA.
'@
        & (Join-Path $PSScriptRoot 'Test-PublicTemplate.ps1')

        $armTemplatePath = Join-Path `
            $labRoot `
            'templates\azuredeploy\entra-cba-playwright-infrastructure.json'
        if (-not (Test-Path -LiteralPath $armTemplatePath -PathType Leaf)) {
            throw "Checked-in ARM template not found at '$armTemplatePath'."
        }
        $armTemplate = Get-Content -LiteralPath $armTemplatePath -Raw | ConvertFrom-Json
        $expectedOutputNames = @(
            'appUrl',
            'crlUrl',
            'logAnalyticsWorkspaceName',
            'keyVaultPrivateEndpointName',
            'publisherClientId',
            'publisherIdentityName',
            'publisherPrincipalId',
            'publisherResourceId',
            'runnerOutboundIpAddress',
            'runnerSubnetId',
            'runnerVaultName',
            'staticWebAppName',
            'workloadClientId',
            'workloadIdentityName',
            'workloadPrincipalId',
            'workloadResourceId',
            'virtualNetworkName'
        )
        $actualOutputNames = @(
            $armTemplate.outputs.PSObject.Properties.Name |
                Sort-Object -CaseSensitive
        )
        if (
            $actualOutputNames.Count -ne $expectedOutputNames.Count -or
            (Compare-Object `
                ($expectedOutputNames | Sort-Object -CaseSensitive) `
                $actualOutputNames `
                -CaseSensitive)
        ) {
            throw 'The checked-in ARM template outputs do not match the exact deployment contract.'
        }

        $pdfPath = Join-Path `
            $labRoot `
            'docs\entra-cba-playwright-e2e-test-results-and-runbook.pdf'
        $expectedPdfSha256 = '3652ac22fa468a13374fcd2c6a74c339ca44a9da94554ef0c269982304e5195a'
        if (-not (Test-Path -LiteralPath $pdfPath -PathType Leaf)) {
            throw "Published PDF not found at '$pdfPath'."
        }
        $actualPdfSha256 = (
            Get-FileHash -LiteralPath $pdfPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualPdfSha256 -cne $expectedPdfSha256) {
            throw 'The checked-in PDF does not match its published SHA-256.'
        }

        Assert-PublicProof
        Write-Host 'PUBLIC_PROOF_PASS: pinned published evidence is an exact privacy-safe 37/37 pass.'
        Write-Host 'This result verifies published evidence; it does not perform a new CBA sign-in.'
    }

    'EvidenceReplay' {
        Write-TierBanner @'
TIER B -- AUTHORIZED READ-ONLY EVIDENCE REPLAY
Re-queries live Azure and GitHub state and re-hashes retained local receipts. It does not generate
a new CBA run. Success requires an exact 37 passed, 0 failed, 37 total result.
'@
        $showProofParameters = @{}
        if ($PSBoundParameters.ContainsKey('ExpectedRunId')) {
            $showProofParameters.ExpectedRunId = $ExpectedRunId
        }
        if ($PSBoundParameters.ContainsKey('ExpectedHeadSha')) {
            $showProofParameters.ExpectedHeadSha = $ExpectedHeadSha
        }
        if ($PSBoundParameters.ContainsKey('ExpectedPositiveCorrelationId')) {
            $showProofParameters.ExpectedPositiveCorrelationId = $ExpectedPositiveCorrelationId
        }
        if ($PSBoundParameters.ContainsKey('ExpectedNegativeCorrelationId')) {
            $showProofParameters.ExpectedNegativeCorrelationId = $ExpectedNegativeCorrelationId
        }

        $proof = Invoke-E2eProofReplay -Parameters $showProofParameters
        Write-Host (
            "EVIDENCE_REPLAY_PASS: $($proof.summary.passed)/$($proof.summary.total), " +
            'read-only replay of retained evidence.'
        )
    }

    'FreshRun' {
        if (
            -not $Repository -or
            $Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
        ) {
            throw 'FreshRun requires -Repository in exact owner/name form.'
        }
        if ([string]::IsNullOrWhiteSpace($InterferingPolicyIdsCsv)) {
            throw 'FreshRun requires the reviewed comma-separated interfering policy IDs.'
        }
        if (-not $ConfirmExclusiveConditionalAccessWindow) {
            throw (
                'FreshRun requires -ConfirmExclusiveConditionalAccessWindow because the bounded ' +
                'Conditional Access transaction cannot use ETag preconditions.'
            )
        }

        $infrastructurePath = Join-Path $stateDirectory 'infrastructure.json'
        if (-not (Test-Path -LiteralPath $infrastructurePath -PathType Leaf)) {
            throw 'Infrastructure state is missing. Run Bootstrap-PostDeploy.ps1 first.'
        }
        $infrastructure = Get-Content -LiteralPath $infrastructurePath -Raw | ConvertFrom-Json

        Write-TierBanner @'
TIER C -- NEW END-TO-END 37-CHECK PROOF
Creates one new ephemeral cloud/browser run, regenerates all four local controls against that
proof-set ID, performs the bounded Conditional Access positive/negative transaction, restores
policy state, and then requires exactly 37 passed and 0 failed.
'@
        . (Join-Path $PSScriptRoot 'Confirm-TenantMutationConsent.ps1')
        Confirm-TenantMutationConsent `
            -TenantId $infrastructure.tenantId `
            -SubscriptionId $infrastructure.subscriptionId `
            -Repository $Repository `
            -ConfirmSwitch ([bool]$ConfirmTenantMutations) `
            -PendingMutations @(
                "Dispatch '$WorkflowFile' and create/delete one ephemeral Azure runner"
                'Perform fresh certificate-backed browser sign-ins'
                'Temporarily enable the exact lab Conditional Access policy'
                'Temporarily add the lab app to reviewed managed-policy exclusions'
                'Recover and verify any prior incomplete Conditional Access isolation transaction'
                'Restore and verify every Conditional Access policy before evidence polling'
            )

        $verificationLockPath = Join-Path $stateDirectory 'lab-lifecycle.lock'
        try {
            $verificationLock = [IO.File]::Open(
               $verificationLockPath,
               [IO.FileMode]::OpenOrCreate,
               [IO.FileAccess]::ReadWrite,
               [IO.FileShare]::None
            )
        }
        catch [IO.IOException] {
            throw 'Another bootstrap, FreshRun, or teardown owns the exclusive lab lifecycle lock.'
        }
        try {
        $priorIsolationStatus = Get-ConditionalAccessIsolationStatus `
            -TenantId $infrastructure.tenantId
        if ($priorIsolationStatus -and $priorIsolationStatus -cne 'restored') {
            Write-Host 'Recovering the prior Conditional Access isolation transaction first.'
            & (Join-Path $PSScriptRoot 'Invoke-ConditionalAccessProof.ps1') `
               -TenantId $infrastructure.tenantId `
               -InterferingPolicyIdsCsv $InterferingPolicyIdsCsv `
               -ConfirmExclusiveConditionalAccessWindow `
               -RestoreIsolationOnly
            $priorIsolationStatus = Get-ConditionalAccessIsolationStatus `
               -TenantId $infrastructure.tenantId
            if ($priorIsolationStatus -cne 'restored') {
               throw 'Prior Conditional Access isolation recovery was not verified.'
            }
        }

        $runnerStatePath = Join-Path $stateDirectory 'runner.json'
        $previousProofSetId = if (Test-Path -LiteralPath $runnerStatePath -PathType Leaf) {
            (Get-Content -LiteralPath $runnerStatePath -Raw | ConvertFrom-Json).proofSetId
        }
        else {
            $null
        }
        $freshRunStartedAt = [DateTimeOffset]::UtcNow
        $runnerParameters = @{
            Repository = $Repository
            WorkflowFile = $WorkflowFile
            Dispatch = $true
        }
        if ($Ref) {
            $runnerParameters.Ref = $Ref
        }
        & (Join-Path $PSScriptRoot 'Start-EphemeralGitHubRunner.ps1') @runnerParameters

        if (-not (Test-Path -LiteralPath $runnerStatePath -PathType Leaf)) {
            throw 'The fresh cloud run did not create runner proof state.'
        }
        $runner = Get-Content -LiteralPath $runnerStatePath -Raw | ConvertFrom-Json
        if (
            $runner.proofSetId -notmatch '^[a-f0-9]{64}$' -or
            $runner.proofSetId -ceq $previousProofSetId -or
            [DateTimeOffset]::Parse([string]$runner.completedAt).ToUniversalTime() -lt
                $freshRunStartedAt.AddMinutes(-1) -or
            $runner.workflowFinalStatus -ne 'completed' -or
            $runner.workflowFinalConclusion -ne 'success' -or
            $runner.aciContainerDeleted -ne $true -or
            $runner.githubRunnerDeregistered -ne $true
        ) {
            throw 'The cloud gate did not produce a new, successful, fully cleaned proof set.'
        }

        Write-Host 'Generating four local controls bound to the new cloud proof set.'
        & (Join-Path $PSScriptRoot 'Invoke-LocalFeasibility.ps1') `
            -Headed `
            -ProofSetId $runner.proofSetId
        & (Join-Path $PSScriptRoot 'Invoke-LocalFeasibility.ps1') `
            -WrongOrigin `
            -ProofSetId $runner.proofSetId
        & (Join-Path $PSScriptRoot 'Invoke-LocalFeasibility.ps1') `
            -Repeat 5 `
            -ProofSetId $runner.proofSetId
        & (Join-Path $PSScriptRoot 'Invoke-LocalFeasibility.ps1') `
            -ReuseSession `
            -ProofSetId $runner.proofSetId

        Write-Host 'Running the bounded Conditional Access positive/negative proof and restoration.'
        & (Join-Path $PSScriptRoot 'Invoke-ConditionalAccessProof.ps1') `
            -TenantId $infrastructure.tenantId `
            -BrowserScenario Both `
            -InterferingPolicyIdsCsv $InterferingPolicyIdsCsv `
            -ConfirmExclusiveConditionalAccessWindow `
            -PropagationSeconds $PropagationSeconds `
            -NegativeFinalizationSeconds $NegativeFinalizationSeconds `
            -EvidenceTimeoutMinutes $EvidenceTimeoutMinutes

        $positive = Get-Content `
            -LiteralPath (Join-Path $stateDirectory 'auth-strength-positive.json') `
            -Raw | ConvertFrom-Json
        $negative = Get-Content `
            -LiteralPath (Join-Path $stateDirectory 'auth-strength-negative.json') `
            -Raw | ConvertFrom-Json
        if (
            $positive.proofSetId -cne $runner.proofSetId -or
            $negative.proofSetId -cne $runner.proofSetId
        ) {
            throw 'Conditional Access evidence is not bound to the new cloud proof set.'
        }

        $proof = Invoke-E2eProofReplay -Parameters @{
            ExpectedRunId = [long]$runner.workflowRunId
            ExpectedHeadSha = [string]$runner.workflowHeadSha
            ExpectedPositiveCorrelationId = [guid]$positive.correlationId
            ExpectedNegativeCorrelationId = [guid]$negative.correlationId
        }
        Write-Host (
            "FRESH_RUN_PASS: $($proof.summary.passed)/$($proof.summary.total) checks passed " +
            'for one newly generated proof set; policy restoration and cleanup are included.'
        )
        }
        finally {
            $verificationLock.Dispose()
        }
    }
}
