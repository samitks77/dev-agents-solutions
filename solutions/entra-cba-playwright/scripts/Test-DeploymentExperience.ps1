[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$labRoot = Split-Path -Parent $PSScriptRoot
$repositoryRoot = (& git -C $labRoot rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Deployment-experience tests must run inside the repository.'
}

function Assert-ExactSet {
    param(
        [Parameter(Mandatory)][object[]]$Actual,
        [Parameter(Mandatory)][object[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actualSorted = @($Actual | Sort-Object -CaseSensitive)
    $expectedSorted = @($Expected | Sort-Object -CaseSensitive)
    if (
        $actualSorted.Count -ne $expectedSorted.Count -or
        (Compare-Object $expectedSorted $actualSorted -CaseSensitive)
    ) {
        throw "$Label does not match the exact expected set."
    }
}

$templatePath = Join-Path `
    $labRoot `
    'templates\azuredeploy\entra-cba-playwright-infrastructure.json'
$template = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
Assert-ExactSet `
    -Actual @($template.parameters.PSObject.Properties.Name) `
    -Expected @(
        'confirmManagedIdentityServicePrincipals',
        'location',
        'networkProfile',
        'tags'
    ) `
    -Label 'Portal template parameters'
Assert-ExactSet `
    -Actual @($template.parameters.networkProfile.allowedValues) `
    -Expected @('10-range', '172-range', '192-range') `
    -Label 'Portal network profiles'
Assert-ExactSet `
    -Actual @($template.parameters.confirmManagedIdentityServicePrincipals.allowedValues) `
    -Expected @($true) `
    -Label 'Managed-identity directory acknowledgement'
if (
    $template.parameters.confirmManagedIdentityServicePrincipals.PSObject.Properties.Name -contains
        'defaultValue'
) {
    throw 'The managed-identity directory acknowledgement must not have a default.'
}
if (
    @($template.resources).Count -ne 1 -or
    $template.resources[0].type -cne 'Microsoft.Resources/deployments' -or
    $template.metadata._generator.version -notmatch '^0\.41\.2\.'
) {
    throw 'The checked-in template is not the portal wrapper compiled by pinned Bicep v0.41.2.'
}

$verificationWorkflowPath = Join-Path `
    $repositoryRoot `
    '.github\workflows\entra-cba-verification.yml'
$verificationWorkflow = Get-Content -LiteralPath $verificationWorkflowPath -Raw
if (
    $verificationWorkflow -match '(?m)^\s*inputs\s*:' -or
    $verificationWorkflow -match '\bEvidenceReplay\b' -or
    $verificationWorkflow -match '\bFreshRun\b' -or
    $verificationWorkflow -notmatch '\-Tier PublicProof\b'
) {
    throw 'The GitHub verification button must expose only safe public-proof verification.'
}

$bootstrapPath = Join-Path $PSScriptRoot 'Bootstrap-PostDeploy.ps1'
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw
$bootstrapImportIndex = $bootstrap.IndexOf("'Import-InfrastructureState.ps1'")
$bootstrapConsentIndex = $bootstrap.IndexOf('Confirm-TenantMutationConsent `')
$bootstrapRbacRepairIndex = $bootstrap.IndexOf('Remove-ExactPublisherAssignment `')
$bootstrapPublishIndex = $bootstrap.IndexOf("'Publish-LabAssets.ps1'")
if (
    $bootstrapImportIndex -lt 0 -or
    $bootstrapConsentIndex -le $bootstrapImportIndex -or
    $bootstrapRbacRepairIndex -le $bootstrapConsentIndex -or
    $bootstrapPublishIndex -le $bootstrapRbacRepairIndex -or
    $bootstrap -match '\bskipPublish\b|\bRepublishAssets\b' -or
    $bootstrap -notmatch 'lab-lifecycle\.lock' -or
    $bootstrap -notmatch 'Set-StrictMode\s+-Version\s+1\.0' -or
    $bootstrap -match 'Set-StrictMode\s+-Version\s+Latest' -or
    $bootstrap -notmatch
        '\[ValidateSet\(''entra-cba-poc'',\s*IgnoreCase\s*=\s*\$false\)\]' -or
    $bootstrap -notmatch 'This lab was torn down'
) {
    throw 'Bootstrap ordering or unconditional credential publication has regressed.'
}

$deploymentScript = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Deploy-Infrastructure.ps1') `
    -Raw
if (
    $deploymentScript -notmatch
        '\[switch\]\$ConfirmManagedIdentityServicePrincipals' -or
    $deploymentScript -notmatch
        '-not \$WhatIf -and -not \$ConfirmManagedIdentityServicePrincipals' -or
    $deploymentScript -match
        'Assert-LabVaultRbac[^\r\n]*-RepairLegacyAssignments'
) {
    throw 'Infrastructure deployment lacks explicit identity consent or safe RBAC handling.'
}

$configureGithub = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Configure-GitHubOidc.ps1') `
    -Raw
$startRunner = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Start-EphemeralGitHubRunner.ps1') `
    -Raw
if (
    $configureGithub -notmatch 'unexpectedCredentials' -or
    $configureGithub -notmatch 'Assert-ExactFederatedCredentialSet' -or
    $configureGithub -notmatch
        '\[ValidateSet\(''entra-cba-poc'',\s*IgnoreCase\s*=\s*\$false\)\]' -or
    $configureGithub -notmatch
        "Assert-ExactStringSet[\s\S]*-Label 'GitHub environment secret names'" -or
    $startRunner -notmatch 'Assert-ExactFederatedCredentialSet'
) {
    throw 'The exact workload federated-credential set is not enforced end to end.'
}
if (
    $startRunner -notmatch 'runner-operation\.json' -or
    $startRunner -notmatch 'runner-operation\.lock' -or
    $startRunner -notmatch 'Write-RunnerStateAtomically' -or
    $startRunner -notmatch '\$container\.tags\.operationId\s+-cne\s+\$LauncherId' -or
    $startRunner -notmatch
        '\[string\]\$container\.tags\.repositoryId\s+-cne\s+\$RepositoryId' -or
    $startRunner -notmatch 'Remove-ExactRepositoryRunner' -or
    $startRunner -match
        'foreach\s*\(\$existingContainer\s+in\s+\$existingContainers\)'
) {
    throw 'Ephemeral runner creation and cleanup lack exact journal-bound ownership.'
}

$runnerNetworkSource = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Runner-Network.ps1') `
    -Raw
if (
    $runnerNetworkSource -notmatch
        "PSObject\.Properties\.Name\s+-contains\s+'routeTable'" -or
    $runnerNetworkSource -match '\$runnerSubnet\.routeTable\.id\)'
) {
    throw 'Runner network validation is not null-safe for the required no-route-table topology.'
}

$teardownScript = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Remove-EntraCbaLab.ps1') `
    -Raw
if (
    $teardownScript -notmatch 'conditional-access-isolation\.lock' -or
    $teardownScript -notmatch "\.status\s+-cne\s+'restored'" -or
    $teardownScript -notmatch
        '\$absenceDeadline\s*=\s*\$appearanceDeadline\.AddSeconds\(30\)' -or
    $teardownScript -notmatch 'Assert-ReconciledGraphAbsence'
) {
    throw 'Teardown is not guarded by the restored Conditional Access isolation transaction.'
}

$verificationScriptPath = Join-Path $PSScriptRoot 'Invoke-EntraCbaVerification.ps1'
$verificationScript = Get-Content -LiteralPath $verificationScriptPath -Raw
if (
    $verificationScript -notmatch 'Set-StrictMode\s+-Version\s+1\.0' -or
    $verificationScript -match 'Set-StrictMode\s+-Version\s+Latest'
) {
    throw 'FreshRun must allow optional members in dynamic Azure and Graph responses.'
}
$freshRunStart = $verificationScript.IndexOf("    'FreshRun' {")
if ($freshRunStart -lt 0) {
    throw 'The unified verifier does not contain FreshRun.'
}
$freshRun = $verificationScript.Substring($freshRunStart)
$previousIndex = -1
foreach ($fragment in @(
    '-RestoreIsolationOnly'
    "'Start-EphemeralGitHubRunner.ps1'",
    '-Headed `',
    '-WrongOrigin `',
    '-Repeat 5 `',
    '-ReuseSession `',
    '-BrowserScenario Both `',
    'Invoke-E2eProofReplay -Parameters'
)) {
    $currentIndex = $freshRun.IndexOf($fragment)
    if ($currentIndex -le $previousIndex) {
        throw "FreshRun does not execute '$fragment' in the required proof order."
    }
    $previousIndex = $currentIndex
}
foreach ($requiredAssertion in @(
    '[int]$proof.summary.total -ne 37',
    '[int]$proof.summary.passed -ne 37',
    '[int]$proof.summary.failed -ne 0'
)) {
    if (-not $verificationScript.Contains($requiredAssertion, [StringComparison]::Ordinal)) {
        throw "The unified verifier is missing strict assertion '$requiredAssertion'."
    }
}

$keyVaultRbacPath = Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1'
$keyVaultRbac = Get-Content -LiteralPath $keyVaultRbacPath -Raw
if (
    $keyVaultRbac -match 'foreach\s*\(\$assignment\s+in\s+\$directOfficerAssignments\)' -or
    $keyVaultRbac -notmatch '\$repairableAssignments\s*=\s*@\(' -or
    $keyVaultRbac -notmatch '\$_.principalId\s+-eq\s+\$publisherPrincipalId' -or
    $keyVaultRbac -notmatch '\$_.id\s+-ieq\s+\$RepairableAssignmentId'
) {
    throw 'Key Vault RBAC repair is not restricted to the exact recorded assignment ID.'
}
if (
    $keyVaultRbac -notmatch '\$appearanceDeadline\s*=\s*\(Get-Date\)\.AddMinutes\(10\)' -or
    $keyVaultRbac -notmatch
        '\$cleanupDeadline\s*=\s*\$appearanceDeadline\.AddMinutes\(2\)' -or
    $keyVaultRbac -match '\$lateAbsenceWindow' -or
    $keyVaultRbac -notmatch 'Microsoft\.KeyVault/vaults/secrets/update/action' -or
    $keyVaultRbac -notmatch 'Microsoft\.Authorization/roleDefinitions/write'
) {
    throw 'RBAC recovery does not enforce the full consistency and escalation contract.'
}
if (
    $keyVaultRbac -match
        '(?s)az role assignment list\s+`?\r?\n\s+--scope[^\r\n]*\r?\n(?:[^\r\n]*\r?\n){0,4}\s+--all'
) {
    throw 'A scoped Azure role-assignment query also uses the incompatible --all option.'
}
if (
    $keyVaultRbac -match
        '\$publisherMutationAssignments\s*\|\s*Where-Object[\s\S]*\$AssignmentId'
) {
    throw 'Final publisher authorization proof excludes the revoked assignment ID.'
}

$publisherPath = Join-Path $PSScriptRoot 'Publish-LabAssets.ps1'
$publisher = Get-Content -LiteralPath $publisherPath -Raw
if (
    $publisher -match '\$repairableStaleAssignments' -or
    $publisher -notmatch 'publisher-operation\.json' -or
    $publisher -notmatch 'publisher-operation\.lock' -or
    $publisher -notmatch 'Write-PublisherOperationState' -or
    $publisher -notmatch 'Remove-ExactPublisherAssignment' -or
    $publisher -notmatch 'ConfirmedLiveAssignment' -or
    $publisher -notmatch 'RequireAppearanceWindow'
) {
    throw 'Credential publication does not use locked, recoverable exact-ID RBAC state.'
}
$publisherRecoveryIndex = $publisher.IndexOf('Remove-ExactPublisherAssignment `')
$publisherContainerDiscoveryIndex = $publisher.IndexOf('$stalePublisherContainers = @(')
if (
    $publisherRecoveryIndex -lt 0 -or
    $publisherContainerDiscoveryIndex -le $publisherRecoveryIndex -or
    $publisher -notmatch '\$effectiveContainerName\s*=\s*\$PublisherContainerName' -or
    $publisher -notmatch "If-None-Match'\]\s*=\s*'\*'" -or
    $publisher -notmatch 'Remove-ExactPublisherContainerGroup'
) {
    throw 'Publisher privilege recovery or cloud-scoped container leasing has regressed.'
}

$entraConfiguration = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Configure-EntraCba.ps1') `
    -Raw
$entraJournalIndex = $entraConfiguration.IndexOf('$entraOperation = [ordered]@{')
$entraUserCreateIndex = $entraConfiguration.IndexOf(
    "Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/users'"
)
if (
    $entraConfiguration -notmatch 'entra-operation\.json' -or
    $entraConfiguration -notmatch 'entra-operation\.lock' -or
    $entraConfiguration -notmatch 'entra-baseline-operation\.json' -or
    $entraConfiguration -notmatch 'ownershipMarker' -or
    $entraConfiguration -notmatch 'Get-ReconciledGraphMatches' -or
    $entraConfiguration -notmatch 'Write-EntraStateAtomically' -or
    $entraJournalIndex -lt 0 -or
    $entraUserCreateIndex -le $entraJournalIndex
) {
    throw 'Entra object creation is not preceded by durable recovery state.'
}
if (
    $entraConfiguration -notmatch
        "membershipStatus\s+-in\s+@\('planned',\s*'created'\)" -or
    $entraConfiguration -match
        'Remove-Item[^\r\n]*\$teardownStatePath'
) {
    throw 'Membership recovery or completed-teardown state preservation has regressed.'
}
if (
    $entraConfiguration -notmatch
        'Get-GraphCollection -Uri \$pkiCollectionUri'
) {
    throw 'PKI reconciliation does not traverse every Microsoft Graph result page.'
}
foreach ($statusName in @(
    'groupStatus',
    'testUserStatus',
    'pkiStatus',
    'caStatus'
)) {
    if (
        $entraConfiguration -notmatch
            "$statusName\s+-in\s+@\('planned',\s*'created'\)"
    ) {
        throw "Created Entra object '$statusName' lacks an appearance-recovery window."
    }
}

$applicationDeployment = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Deploy-TestApp.ps1') `
    -Raw
$applicationJournalIndex = $applicationDeployment.IndexOf(
    'Write-ApplicationStateAtomically `'
)
$applicationCreateIndex = $applicationDeployment.IndexOf('az ad app create `')
$servicePrincipalPlanIndex = $applicationDeployment.IndexOf(
    "`$operation.servicePrincipalStatus = 'planned'"
)
$servicePrincipalCreateIndex = $applicationDeployment.IndexOf('az ad sp create `')
if (
    $applicationDeployment -notmatch 'application-operation\.json' -or
    $applicationDeployment -notmatch 'application-operation\.lock' -or
    $applicationDeployment -notmatch 'Get-ReconciledApplications' -or
    $applicationDeployment -notmatch 'Get-ReconciledServicePrincipals' -or
    $applicationJournalIndex -lt 0 -or
    $applicationCreateIndex -le $applicationJournalIndex -or
    $servicePrincipalPlanIndex -lt 0 -or
    $servicePrincipalCreateIndex -le $servicePrincipalPlanIndex
) {
    throw 'Application and service-principal creation lack durable recovery ordering.'
}
if (
    $applicationDeployment -notmatch
        "appStatus\s+-in\s+@\('planned',\s*'created'\)" -or
    $applicationDeployment -notmatch
        "servicePrincipalStatus\s+-in\s+@\('planned',\s*'created'\)" -or
    $applicationDeployment -notmatch
        '\$absenceDeadline\s*=\s*\$appearanceDeadline\.AddSeconds\(30\)'
) {
    throw 'Created application objects are not covered by the appearance-recovery window.'
}

$conditionalAccessConfiguration = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Configure-ConditionalAccess.ps1') `
    -Raw
$conditionalAccessJournalIndex = $conditionalAccessConfiguration.IndexOf(
    '$conditionalAccessOperation = if ('
)
$conditionalAccessCreateIndex = $conditionalAccessConfiguration.IndexOf(
    'Invoke-GraphJson -Method POST -Uri $policiesUri'
)
if (
    $conditionalAccessConfiguration -notmatch 'conditional-access-operation\.json' -or
    $conditionalAccessConfiguration -notmatch 'conditional-access-operation\.lock' -or
    $conditionalAccessConfiguration -notmatch '\(Get-Date\)\.AddMinutes\(10\)' -or
    $conditionalAccessJournalIndex -lt 0 -or
    $conditionalAccessCreateIndex -le $conditionalAccessJournalIndex
) {
    throw 'Conditional Access creation lacks serialized, reconcilable ownership state.'
}
if (
    $conditionalAccessConfiguration -notmatch 'function Get-GraphCollection' -or
    $conditionalAccessConfiguration -notmatch
        "policyStatus\s+-in\s+@\('planned',\s*'created'\)" -or
    $conditionalAccessConfiguration -notmatch
        '\$absenceDeadline\s*=\s*\$appearanceDeadline\.AddSeconds\(30\)' -or
    $conditionalAccessConfiguration -notmatch
        '\$provisionalConditionalAccessState'
) {
    throw 'Conditional Access recovery is not paginated across the full appearance window.'
}

if (
    $bootstrap -notmatch 'lab-lifecycle\.lock' -or
    $verificationScript -notmatch 'lab-lifecycle\.lock' -or
    $teardownScript -notmatch 'lab-lifecycle\.lock'
) {
    throw 'Bootstrap, FreshRun, and teardown do not share one lifecycle lock.'
}

if (
    $configureGithub -notmatch '\$legacyGithubState' -or
    $configureGithub -notmatch '\$repoIdentity\.owner\.id' -or
    $configureGithub -notmatch '\$liveLegacySecretNames' -or
    $configureGithub -notmatch 'Write-GitHubState -State \$migratedGithubState' -or
    $configureGithub -notmatch
        "Live legacy GitHub environment secret names"
) {
    throw 'Legacy GitHub ownership state lacks exact live validation and atomic migration.'
}

$importInfrastructure = Get-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'Import-InfrastructureState.ps1') `
    -Raw
if (
    $importInfrastructure -notmatch 'infrastructure-import\.lock' -or
    $importInfrastructure -notmatch 'dependent lab state exists' -or
    $importInfrastructure -notmatch 'Write-InfrastructureStateAtomically'
) {
    throw 'Infrastructure import does not preserve dependent-state binding.'
}

. $keyVaultRbacPath
$roleAssignmentWriter = [pscustomobject]@{
    permissions = @(
        [pscustomobject]@{
            actions = @('Microsoft.Authorization/roleAssignments/write')
            dataActions = @()
            notActions = @()
            notDataActions = @()
        }
    )
}
if (-not (Test-RoleDefinitionGrantsSecretMutation -RoleDefinition $roleAssignmentWriter)) {
    throw 'RBAC guardrail missed control-plane role-assignment self-elevation.'
}
$excludedRoleAssignmentWriter = [pscustomobject]@{
    permissions = @(
        [pscustomobject]@{
            actions = @('Microsoft.Authorization/roleAssignments/write')
            dataActions = @()
            notActions = @('Microsoft.Authorization/roleAssignments/write')
            notDataActions = @()
        }
    )
}
if (Test-RoleDefinitionGrantsSecretMutation -RoleDefinition $excludedRoleAssignmentWriter) {
    throw 'RBAC guardrail ignored an exact control-plane action exclusion.'
}
foreach ($capability in @(
    @{
        action = 'Microsoft.KeyVault/vaults/secrets/write'
        collection = 'actions'
        label = 'control-plane secret write'
    }
    @{
        action = 'Microsoft.KeyVault/vaults/secrets/update/action'
        collection = 'dataActions'
        label = 'secret update'
    }
    @{
        action = 'Microsoft.Authorization/roleDefinitions/write'
        collection = 'actions'
        label = 'role-definition self-elevation'
    }
)) {
    $permission = [ordered]@{
        actions = @()
        dataActions = @()
        notActions = @()
        notDataActions = @()
    }
    $permission[$capability.collection] = @($capability.action)
    $role = [pscustomobject]@{
        permissions = @([pscustomobject]$permission)
    }
    if (-not (Test-RoleDefinitionGrantsSecretMutation -RoleDefinition $role)) {
        throw "RBAC guardrail missed $($capability.label)."
    }
}

$publisherOperationTestPath = [IO.Path]::GetTempFileName()
$testSubscriptionId = [guid]::NewGuid().ToString()
$testPrincipalId = [guid]::NewGuid().ToString()
$testAssignmentName = [guid]::NewGuid().ToString()
$testRoleDefinitionId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
$testVaultId = (
    "/subscriptions/$testSubscriptionId/resourceGroups/test/providers/" +
    'Microsoft.KeyVault/vaults/test'
)
$testAssignmentId = (
    "$testVaultId/providers/Microsoft.Authorization/roleAssignments/$testAssignmentName"
)
try {
    $testOperation = [ordered]@{
        assignmentId = $testAssignmentId
        assignmentName = $testAssignmentName
        publisherPrincipalId = $testPrincipalId
        roleDefinitionId = $testRoleDefinitionId
        schemaVersion = 1
        status = 'planned'
        vaultId = $testVaultId
    }
    $testOperation |
        ConvertTo-Json |
        Set-Content -LiteralPath $publisherOperationTestPath -Encoding utf8NoBOM
    $resolvedAssignmentId = Get-RecordedPublisherAssignmentId `
        -OperationStatePath $publisherOperationTestPath `
        -PublisherPrincipalId $testPrincipalId `
        -VaultResourceId $testVaultId
    if ($resolvedAssignmentId -cne $testAssignmentId) {
        throw 'Valid publisher operation state did not resolve its exact assignment ID.'
    }

    $testOperation.roleDefinitionId = [guid]::NewGuid().ToString()
    $testOperation |
        ConvertTo-Json |
        Set-Content -LiteralPath $publisherOperationTestPath -Encoding utf8NoBOM
    $roleTamperingRejected = $false
    try {
        Get-RecordedPublisherAssignmentId `
            -OperationStatePath $publisherOperationTestPath `
            -PublisherPrincipalId $testPrincipalId `
            -VaultResourceId $testVaultId | Out-Null
    }
    catch {
        $roleTamperingRejected = $true
    }
    if (-not $roleTamperingRejected) {
        throw 'Publisher operation state accepted a different role definition.'
    }

    $testOperation.roleDefinitionId = $testRoleDefinitionId
    $testOperation.publisherPrincipalId = [guid]::NewGuid().ToString()
    $testOperation |
        ConvertTo-Json |
        Set-Content -LiteralPath $publisherOperationTestPath -Encoding utf8NoBOM
    $tamperingRejected = $false
    try {
        Get-RecordedPublisherAssignmentId `
            -OperationStatePath $publisherOperationTestPath `
            -PublisherPrincipalId $testPrincipalId `
            -VaultResourceId $testVaultId | Out-Null
    }
    catch {
        $tamperingRejected = $true
    }
    if (-not $tamperingRejected) {
        throw 'Publisher operation state accepted a different principal.'
    }
}
finally {
    Remove-Item -LiteralPath $publisherOperationTestPath -Force
}

. (Join-Path $PSScriptRoot 'Federated-Credential.ps1')
$validFederatedCredential = [pscustomobject]@{
    audiences = @('api://AzureADTokenExchange')
    issuer = 'https://token.actions.githubusercontent.com'
    name = 'github-entra-cba-poc'
    subject = 'repo:owner@1/repository@2:environment:entra-cba-poc'
}
Assert-ExactFederatedCredentialSet `
    -Credentials @($validFederatedCredential) `
    -ExpectedName $validFederatedCredential.name `
    -ExpectedIssuer $validFederatedCredential.issuer `
    -ExpectedSubject $validFederatedCredential.subject `
    -ExpectedAudience $validFederatedCredential.audiences[0] | Out-Null
$additionalCredentialRejected = $false
try {
    Assert-ExactFederatedCredentialSet `
        -Credentials @($validFederatedCredential, $validFederatedCredential) `
        -ExpectedName $validFederatedCredential.name `
        -ExpectedIssuer $validFederatedCredential.issuer `
        -ExpectedSubject $validFederatedCredential.subject `
        -ExpectedAudience $validFederatedCredential.audiences[0] | Out-Null
}
catch {
    $additionalCredentialRejected = $true
}
if (-not $additionalCredentialRejected) {
    throw 'Federated credential guardrail accepted an additional trust path.'
}

. (Join-Path $PSScriptRoot 'Teardown-State.ps1')
if ('github.json' -in @(Get-EntraTeardownRetirableStateFileNames)) {
    throw 'PKI retirement must preserve GitHub ownership state for live remote objects.'
}
$teardownTestRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "entra-cba-teardown-$([guid]::NewGuid().ToString('N'))"
$teardownTestTenantId = [guid]::NewGuid().ToString()
try {
    foreach ($caseName in @('valid', 'tampered', 'unrestored', 'legacy')) {
        $caseDirectory = Join-Path $teardownTestRoot $caseName
        [IO.Directory]::CreateDirectory($caseDirectory) | Out-Null
        @{
            tenantId = $teardownTestTenantId
        } | ConvertTo-Json |
            Set-Content `
                -LiteralPath (Join-Path $caseDirectory 'entra.json') `
                -Encoding utf8NoBOM
        '{}' | Set-Content `
            -LiteralPath (Join-Path $caseDirectory 'pki.json') `
            -Encoding utf8NoBOM
        '{}' | Set-Content `
            -LiteralPath (Join-Path $caseDirectory 'x509-policy-baseline.json') `
            -Encoding utf8NoBOM
        'preserve' | Set-Content `
            -LiteralPath (Join-Path $caseDirectory 'infrastructure.json') `
            -Encoding utf8NoBOM
    }

    $validDirectory = Join-Path $teardownTestRoot 'valid'
    $validRecord = New-EntraTeardownStateRecord `
        -StateDirectory $validDirectory `
        -TenantId $teardownTestTenantId
    Write-EntraTeardownStateAtomically `
        -Path (Join-Path $validDirectory 'entra-teardown.json') `
        -State $validRecord
    $activeIsolationLock = [IO.File]::Open(
        (Join-Path $validDirectory 'conditional-access-isolation.lock'),
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
    $activeTransactionRejected = $false
    try {
        Complete-EntraTeardownStateRetirement `
            -StateDirectory $validDirectory `
            -TenantId $teardownTestTenantId
    }
    catch {
        $activeTransactionRejected = $true
    }
    finally {
        $activeIsolationLock.Dispose()
    }
    if (-not $activeTransactionRejected) {
        throw 'Completed teardown retirement accepted an active isolation transaction.'
    }
    Complete-EntraTeardownStateRetirement `
        -StateDirectory $validDirectory `
        -TenantId $teardownTestTenantId
    if (
        (Test-Path -LiteralPath (Join-Path $validDirectory 'entra.json')) -or
        (Test-Path -LiteralPath (Join-Path $validDirectory 'entra-teardown.json')) -or
        -not (Test-Path -LiteralPath (Join-Path $validDirectory 'infrastructure.json'))
    ) {
        throw 'Valid completed teardown state was not retired exactly.'
    }

    $tamperedDirectory = Join-Path $teardownTestRoot 'tampered'
    $tamperedRecord = New-EntraTeardownStateRecord `
        -StateDirectory $tamperedDirectory `
        -TenantId $teardownTestTenantId
    $tamperedStatePath = Join-Path $tamperedDirectory 'entra-teardown.json'
    Write-EntraTeardownStateAtomically `
        -Path $tamperedStatePath `
        -State $tamperedRecord
    '{"changed":true}' | Set-Content `
        -LiteralPath (Join-Path $tamperedDirectory 'pki.json') `
        -Encoding utf8NoBOM
    $tamperingRejected = $false
    try {
        Complete-EntraTeardownStateRetirement `
            -StateDirectory $tamperedDirectory `
            -TenantId $teardownTestTenantId
    }
    catch {
        $tamperingRejected = $true
    }
    if (
        -not $tamperingRejected -or
        -not (Test-Path -LiteralPath $tamperedStatePath)
    ) {
        throw 'Tampered completed teardown state was retired.'
    }

    $unrestoredDirectory = Join-Path $teardownTestRoot 'unrestored'
    @{
        restoredAt = $null
        schemaVersion = 3
        status = 'prepared'
        tenantId = $teardownTestTenantId
    } | ConvertTo-Json |
        Set-Content `
            -LiteralPath (
                Join-Path $unrestoredDirectory 'conditional-access-isolation.json'
            ) `
            -Encoding utf8NoBOM
    $unrestoredRecord = New-EntraTeardownStateRecord `
        -StateDirectory $unrestoredDirectory `
        -TenantId $teardownTestTenantId
    $unrestoredStatePath = Join-Path $unrestoredDirectory 'entra-teardown.json'
    Write-EntraTeardownStateAtomically `
        -Path $unrestoredStatePath `
        -State $unrestoredRecord
    $unrestoredStateRejected = $false
    try {
        Complete-EntraTeardownStateRetirement `
            -StateDirectory $unrestoredDirectory `
            -TenantId $teardownTestTenantId
    }
    catch {
        $unrestoredStateRejected = $true
    }
    if (
        -not $unrestoredStateRejected -or
        -not (Test-Path -LiteralPath $unrestoredStatePath)
    ) {
        throw 'Unrestored Conditional Access isolation state was retired.'
    }

    $legacyDirectory = Join-Path $teardownTestRoot 'legacy'
    @{
        completedAt = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'completed'
        tenantId = $teardownTestTenantId
    } | ConvertTo-Json |
        Set-Content `
            -LiteralPath (Join-Path $legacyDirectory 'entra-teardown.json') `
            -Encoding utf8NoBOM
    $legacyRetirementRejected = $false
    try {
        Complete-EntraTeardownStateRetirement `
            -StateDirectory $legacyDirectory `
            -TenantId $teardownTestTenantId
    }
    catch {
        $legacyRetirementRejected = $true
    }
    if (
        -not $legacyRetirementRejected -or
        -not (Test-Path -LiteralPath (Join-Path $legacyDirectory 'entra-teardown.json'))
    ) {
        throw 'Legacy teardown state bypassed verified deletion read-back.'
    }
}
finally {
    if (Test-Path -LiteralPath $teardownTestRoot) {
        Remove-Item -LiteralPath $teardownTestRoot -Recurse -Force
    }
}

. (Join-Path $PSScriptRoot 'Confirm-TenantMutationConsent.ps1')
function Test-InteractiveLabSession {
    return $false
}

$autoApproveName = 'ENTRA_CBA_BOOTSTRAP_AUTOAPPROVE'
$originalAutoApprove = [Environment]::GetEnvironmentVariable($autoApproveName)
$consentParameters = @{
    TenantId = 'tenant-under-test'
    SubscriptionId = 'subscription-under-test'
    Repository = 'owner-under-test/repository-under-test'
    PendingMutations = @('test-only mutation')
}
try {
    foreach ($testCase in @(
        @{ confirm = $false; autoApprove = $null; label = 'missing switch' },
        @{ confirm = $true; autoApprove = $null; label = 'missing second confirmation' },
        @{ confirm = $true; autoApprove = 'confirmed'; label = 'wrong-case second confirmation' }
    )) {
        [Environment]::SetEnvironmentVariable(
            $autoApproveName,
            $testCase.autoApprove,
            [EnvironmentVariableTarget]::Process
        )
        $wasRejected = $false
        try {
            Confirm-TenantMutationConsent `
                @consentParameters `
                -ConfirmSwitch $testCase.confirm 6>$null
        }
        catch {
            $wasRejected = $true
        }
        if (-not $wasRejected) {
            throw "Consent gate accepted the $($testCase.label) case."
        }
    }

    [Environment]::SetEnvironmentVariable(
        $autoApproveName,
        'CONFIRMED',
        [EnvironmentVariableTarget]::Process
    )
    Confirm-TenantMutationConsent `
        @consentParameters `
        -ConfirmSwitch $true 6>$null
}
finally {
    [Environment]::SetEnvironmentVariable(
        $autoApproveName,
        $originalAutoApprove,
        [EnvironmentVariableTarget]::Process
    )
}

Write-Host 'DEPLOYMENT_EXPERIENCE_TEST_PASS'
