[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Alias('Subscription')]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [Alias('ExpectedTenantId')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository,

    [Parameter(Mandatory)]
    [string]$TestUserUpn,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+(?:\.\d+)+$')]
    [string]$CertificatePolicyOid,

    [string]$DeploymentName,
    [string[]]$AllowedBranches = @('main'),
    [ValidateSet('entra-cba-poc', IgnoreCase = $false)]
    [string]$GitHubEnvironment = 'entra-cba-poc',
    [string]$TestUserDisplayName = 'CBA Playwright Test User',
    [string]$GroupDisplayName = 'grp-entra-cba-playwright-poc',
    [string]$PkiDisplayName = 'Entra CBA Playwright POC PKI',
    [string]$ConditionalAccessPolicyDisplayName = (
        'CA - Entra CBA Playwright POC - Phishing-resistant MFA'
    ),
    [switch]$RegeneratePki,
    [Alias('AllowNonInteractiveTenantMutation')]
    [switch]$ConfirmTenantMutations
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
# Azure CLI and Graph responses omit optional members; retain uninitialized-variable checks
# without making those normal omissions terminating errors in invoked child scripts.
Set-StrictMode -Version 1.0

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$pkiStatePath = Join-Path $stateDirectory 'pki.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$entraTeardownStatePath = Join-Path $stateDirectory 'entra-teardown.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$pkiRoot = Join-Path $labRoot '.lab-secrets'

function Assert-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' is not available."
    }
}

function Assert-LabPkiPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Label,

        [switch]$Directory
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "PKI state does not contain $Label."
    }
    $pathType = if ($Directory) { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
        throw "PKI $Label does not exist at its recorded path."
    }

    $resolvedPkiRoot = [IO.Path]::GetFullPath($pkiRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    ) + [IO.Path]::DirectorySeparatorChar
    $resolvedPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
    if (-not $resolvedPath.StartsWith($resolvedPkiRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "PKI $Label is outside this checkout's ignored .lab-secrets directory."
    }
}

function Assert-LabPkiState {
    param(
        [Parameter(Mandatory)]
        [string]$ExpectedTestUserUpn,

        [Parameter(Mandatory)]
        [string]$ExpectedPolicyOid,

        [Parameter(Mandatory)]
        [string]$ExpectedCrlUrl
    )

    if (-not (Test-Path -LiteralPath $pkiStatePath -PathType Leaf)) {
        throw "PKI state does not exist at '$pkiStatePath'."
    }
    $pki = Get-Content -LiteralPath $pkiStatePath -Raw | ConvertFrom-Json
    if (
        -not [string]::Equals(
            [string]$pki.testUserUpn,
            $ExpectedTestUserUpn,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $pki.policyOid -cne $ExpectedPolicyOid -or
        $pki.crlUrl -cne $ExpectedCrlUrl
    ) {
        throw (
            'Existing PKI state is bound to a different test UPN, policy OID, or CRL URL. ' +
            'Review dependent Entra state, then use -RegeneratePki only for this disposable lab.'
        )
    }

    Assert-LabPkiPath -Path $pki.privateStateDirectory -Label 'private-state directory' -Directory
    Assert-LabPkiPath -Path $pki.pfxPassphrasePath -Label 'PFX passphrase'
    Assert-LabPkiPath -Path $pki.ca.certificatePath -Label 'root CA certificate'
    Assert-LabPkiPath -Path $pki.ca.crlPath -Label 'certificate revocation list'

    $actualCrlHash = (
        Get-FileHash -LiteralPath $pki.ca.crlPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actualCrlHash -cne ([string]$pki.ca.crlSha256).ToLowerInvariant()) {
        throw 'The recorded CRL SHA-256 does not match the current CRL bytes.'
    }

    $expectedCertificateNames = @(
        'cba-playwright-test-mfa',
        'cba-playwright-test-sfa'
    )
    $certificates = @($pki.certificates)
    if (
        $certificates.Count -ne $expectedCertificateNames.Count -or
        (($certificates.name | Sort-Object -CaseSensitive) -join "`n") -cne
        (($expectedCertificateNames | Sort-Object -CaseSensitive) -join "`n")
    ) {
        throw 'PKI state does not contain exactly the expected MFA and single-factor certificates.'
    }
    foreach ($certificate in $certificates) {
        Assert-LabPkiPath `
            -Path $certificate.certificatePath `
            -Label "$($certificate.name) certificate"
        Assert-LabPkiPath `
            -Path $certificate.pfxPath `
            -Label "$($certificate.name) PFX"
        $loadedCertificate = $null
        try {
            $loadedCertificate = (
                [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile(
                    $certificate.certificatePath
                )
            )
            if ($loadedCertificate.Thumbprint -ne $certificate.thumbprint) {
                throw "The recorded thumbprint for '$($certificate.name)' does not match its certificate."
            }
        }
        finally {
            if ($loadedCertificate) {
                $loadedCertificate.Dispose()
            }
        }
    }
}

New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$bootstrapLockPath = Join-Path $stateDirectory 'lab-lifecycle.lock'
try {
    $bootstrapLock = [IO.File]::Open(
        $bootstrapLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another bootstrap, FreshRun, or teardown owns the exclusive lab lifecycle lock.'
}

try {
foreach ($command in @('az', 'gh', 'npm')) {
    Assert-CommandAvailable -Name $command
}

Write-Host '=== Read-only preflight: resolving and verifying deployed infrastructure ==='
$importArguments = @{
    SubscriptionId = $SubscriptionId
    TenantId = $TenantId
    ResourceGroup = $ResourceGroup
}
if ($DeploymentName) {
    $importArguments.DeploymentName = $DeploymentName
}
& (Join-Path $PSScriptRoot 'Import-InfrastructureState.ps1') @importArguments

$infrastructurePath = Join-Path $stateDirectory 'infrastructure.json'
$infrastructure = Get-Content -LiteralPath $infrastructurePath -Raw | ConvertFrom-Json
if (Test-Path -LiteralPath $entraTeardownStatePath -PathType Leaf) {
    $priorTeardownState = Get-Content `
        -LiteralPath $entraTeardownStatePath `
        -Raw | ConvertFrom-Json
    if (
        $priorTeardownState.tenantId -ine $infrastructure.tenantId -or
        $priorTeardownState.status -notin @('completed', 'retiring')
    ) {
        throw 'Existing teardown state is invalid or belongs to another tenant.'
    }
    if (-not $RegeneratePki) {
        throw (
            'This lab was torn down. Rerun bootstrap with -RegeneratePki so the completed ' +
            'teardown record can be validated and retired before new provisioning.'
        )
    }
}
$repositoryIdentity = gh repo view `
    $Repository `
    --json nameWithOwner,viewerPermission | ConvertFrom-Json
if (
    $repositoryIdentity.nameWithOwner -cne $Repository -or
    $repositoryIdentity.viewerPermission -ne 'ADMIN'
) {
    throw "GitHub ADMIN permission for the exact repository '$Repository' is required."
}

Write-Host ''
Write-Host 'Resolved target context (read-only verification complete):'
Write-Host "  Tenant:       $($infrastructure.tenantId)"
Write-Host "  Subscription: $($infrastructure.subscriptionId)"
Write-Host "  Resource group: $($infrastructure.resourceGroup)"
Write-Host "  Repository:   $($repositoryIdentity.nameWithOwner)"
Write-Host ''

. (Join-Path $PSScriptRoot 'Confirm-TenantMutationConsent.ps1')
Confirm-TenantMutationConsent `
    -TenantId $infrastructure.tenantId `
    -SubscriptionId $infrastructure.subscriptionId `
    -Repository $repositoryIdentity.nameWithOwner `
    -ConfirmSwitch ([bool]$ConfirmTenantMutations) `
    -PendingMutations @(
        "Generate or reuse a disposable PKI bound to '$TestUserUpn'"
        'Remove only the exact stale Secrets Officer assignment bound in publisher-operation state'
        'Create and deploy the relying-party test application and public CRL'
        'Publish the PFX and passphrase to the private Key Vault through a temporary identity'
        "Create and scope a disposable Entra test user and group named '$GroupDisplayName'"
        "Configure Entra CBA using PKI container '$PkiDisplayName'"
        "Create or keep Conditional Access policy '$ConditionalAccessPolicyDisplayName' report-only"
        "Configure GitHub OIDC and environment '$GitHubEnvironment' for '$Repository'"
    )

Write-Host ''
Write-Host '=== Step 1/8: Repair and verify exact lab Key Vault RBAC ==='
. (Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1')
$publisherOperationStatePath = Join-Path $stateDirectory 'publisher-operation.json'
$publisherLockPath = Join-Path $stateDirectory 'publisher-operation.lock'
try {
    $publisherLockStream = [IO.File]::Open(
        $publisherLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'A credential publisher operation is active; refusing concurrent RBAC recovery.'
}
try {
    $runnerVault = az keyvault show `
        --name $infrastructure.outputs.runnerVaultName.value `
        --resource-group $infrastructure.resourceGroup `
        --output json | ConvertFrom-Json
    $repairableAssignmentId = Get-RecordedPublisherAssignmentId `
        -OperationStatePath $publisherOperationStatePath `
        -PublisherPrincipalId $infrastructure.outputs.publisherPrincipalId.value `
        -VaultResourceId $runnerVault.id
    if ($repairableAssignmentId) {
        $recordedPublisherOperation = Get-Content `
            -LiteralPath $publisherOperationStatePath `
            -Raw | ConvertFrom-Json
        $secretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' # gitleaks:allow - Public Azure role ID.
        Remove-ExactPublisherAssignment `
            -AssignmentId $repairableAssignmentId `
            -PrincipalId $infrastructure.outputs.publisherPrincipalId.value `
            -VaultResourceId $runnerVault.id `
            -RoleDefinitionId $secretsOfficerRoleId `
            -RequireAppearanceWindow
        if ($recordedPublisherOperation.containerName) {
            if (
                $recordedPublisherOperation.operationId -cne
                    $recordedPublisherOperation.assignmentName
            ) {
                throw 'Publisher journal has invalid cloud-container ownership state.'
            }
            Remove-ExactPublisherContainerGroup `
                -Name $recordedPublisherOperation.containerName `
                -OperationId $recordedPublisherOperation.operationId `
                -ResourceGroup $infrastructure.resourceGroup `
                -RequireAppearanceWindow
        }
        Remove-Item -LiteralPath $publisherOperationStatePath -Force
    }
    Assert-LabVaultRbac `
        -Outputs $infrastructure.outputs `
        -ResourceGroup $infrastructure.resourceGroup | Out-Null
}
finally {
    $publisherLockStream.Dispose()
}

Write-Host ''
Write-Host '=== Step 2/8: Generate or validate the disposable lab PKI ==='
if ($RegeneratePki) {
    . (Join-Path $PSScriptRoot 'Teardown-State.ps1')
    if (Test-Path -LiteralPath $entraTeardownStatePath -PathType Leaf) {
        Complete-EntraTeardownStateRetirement `
            -StateDirectory $stateDirectory `
            -TenantId $infrastructure.tenantId
    }
    $dependentState = @(
        @(
            'conditional-access.json'
            'entra-baseline-context.json'
            'entra-operation.json'
            'entra.json'
            'pki-baseline.json'
            'x509-policy-baseline.json'
        ) | ForEach-Object {
            Join-Path $stateDirectory $_
        } | Where-Object {
            Test-Path -LiteralPath $_
        }
    )
    if ($dependentState.Count -ne 0) {
        throw (
            'PKI regeneration is blocked while Entra or Conditional Access state exists. ' +
            'Run the documented teardown first so the old CA binding cannot be orphaned.'
        )
    }
    & (Join-Path $PSScriptRoot 'New-LabPki.ps1') `
        -TestUserUpn $TestUserUpn `
        -PolicyOid $CertificatePolicyOid `
        -CrlUrl $infrastructure.outputs.crlUrl.value `
        -Force
}
elseif (Test-Path -LiteralPath $pkiStatePath -PathType Leaf) {
    Assert-LabPkiState `
        -ExpectedTestUserUpn $TestUserUpn `
        -ExpectedPolicyOid $CertificatePolicyOid `
        -ExpectedCrlUrl $infrastructure.outputs.crlUrl.value
}
else {
    if (Test-Path -LiteralPath $pkiRoot) {
        throw (
            'Ignored PKI files exist without their binding state. Review them, then use ' +
            '-RegeneratePki to intentionally replace this disposable lab PKI.'
        )
    }
    & (Join-Path $PSScriptRoot 'New-LabPki.ps1') `
        -TestUserUpn $TestUserUpn `
        -PolicyOid $CertificatePolicyOid `
        -CrlUrl $infrastructure.outputs.crlUrl.value
}
Assert-LabPkiState `
    -ExpectedTestUserUpn $TestUserUpn `
    -ExpectedPolicyOid $CertificatePolicyOid `
    -ExpectedCrlUrl $infrastructure.outputs.crlUrl.value

Write-Host ''
Write-Host '=== Step 3/8: Create and deploy the relying-party app and public CRL ==='
& (Join-Path $PSScriptRoot 'Deploy-TestApp.ps1') `
    -TestUsername $TestUserUpn
& (Join-Path $PSScriptRoot 'Test-PublishedCrl.ps1')

Write-Host ''
Write-Host '=== Step 4/8: Publish credentials to the private Key Vault ==='
& (Join-Path $PSScriptRoot 'Publish-LabAssets.ps1')

Write-Host ''
Write-Host '=== Step 5/8: Establish one reusable Microsoft Graph authorization ==='
& (Join-Path $PSScriptRoot 'Connect-EntraCbaLabGraph.ps1') `
    -TenantId $infrastructure.tenantId

Write-Host ''
Write-Host '=== Step 6/8: Configure Entra Certificate-Based Authentication ==='
& (Join-Path $PSScriptRoot 'Configure-EntraCba.ps1') `
    -TenantId $infrastructure.tenantId `
    -TestUserUpn $TestUserUpn `
    -TestUserDisplayName $TestUserDisplayName `
    -GroupDisplayName $GroupDisplayName `
    -PkiDisplayName $PkiDisplayName

Write-Host ''
Write-Host '=== Step 7/8: Create or verify the report-only Conditional Access policy ==='
& (Join-Path $PSScriptRoot 'Configure-ConditionalAccess.ps1') `
    -TenantId $infrastructure.tenantId `
    -PolicyDisplayName $ConditionalAccessPolicyDisplayName `
    -State enabledForReportingButNotEnforced

Write-Host ''
Write-Host '=== Step 8/8: Configure GitHub OIDC and encrypted environment secrets ==='
& (Join-Path $PSScriptRoot 'Configure-GitHubOidc.ps1') `
    -Repository $repositoryIdentity.nameWithOwner `
    -Environment $GitHubEnvironment `
    -AllowedBranches $AllowedBranches

Write-Host ''
Write-Host 'Bootstrap completed. Conditional Access remains report-only.'
Write-Host (
    'Next: run Invoke-EntraCbaVerification.ps1 -Tier FreshRun with the documented ' +
    'maintenance-window confirmations to generate a new 37-check proof.'
)
}
finally {
    $bootstrapLock.Dispose()
}
