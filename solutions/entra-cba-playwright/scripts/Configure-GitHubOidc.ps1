[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repository,
    [ValidateSet('entra-cba-poc', IgnoreCase = $false)]
    [string]$Environment = 'entra-cba-poc',
    [string[]]$AllowedBranches = @('main'),
    [string]$FederatedCredentialName = 'github-entra-cba-poc'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$infrastructureStatePath = Join-Path $stateDirectory 'infrastructure.json'
$githubStatePath = Join-Path $stateDirectory 'github.json'
. (Join-Path $PSScriptRoot 'Runner-Network.ps1')
. (Join-Path $PSScriptRoot 'Federated-Credential.ps1')

foreach ($requiredPath in @($applicationStatePath, $entraStatePath, $infrastructureStatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw "Repository '$Repository' is not an owner/name identifier."
}
if ($Environment -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "Environment '$Environment' contains unsupported characters."
}
if ($AllowedBranches.Count -eq 0) {
    throw 'At least one explicit deployment branch is required.'
}
if (@($AllowedBranches | Where-Object {
    [string]::IsNullOrWhiteSpace($_) -or $_ -match '[*?\[\]]'
}).Count -ne 0) {
    throw 'Deployment branches must be nonempty exact names without glob metacharacters.'
}

$application = Get-Content -LiteralPath $applicationStatePath -Raw | ConvertFrom-Json
$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
$infrastructure = Get-Content -LiteralPath $infrastructureStatePath -Raw | ConvertFrom-Json
if ($application.tenantId -ne $entra.tenantId -or $application.tenantId -ne $infrastructure.tenantId) {
    throw 'Application, Entra, and infrastructure state belong to different tenants.'
}
az account set --subscription $infrastructure.subscriptionId
$azureAccount = az account show --output json | ConvertFrom-Json
if ($azureAccount.id -ne $infrastructure.subscriptionId -or
    $azureAccount.tenantId -ne $infrastructure.tenantId) {
    throw 'Azure CLI context does not match the stored subscription and tenant.'
}
$runnerNetwork = Get-RunnerNetworkContract -Infrastructure $infrastructure

$repo = gh repo view $Repository --json nameWithOwner,viewerPermission | ConvertFrom-Json
if ($repo.nameWithOwner -cne $Repository) {
    throw "GitHub resolved '$Repository' as '$($repo.nameWithOwner)'."
}
if ($repo.viewerPermission -ne 'ADMIN') {
    throw "GitHub ADMIN permission is required to configure '$Repository'."
}
$repoIdentity = gh api "repos/$Repository" | ConvertFrom-Json
if ($repoIdentity.full_name -cne $Repository -or
    -not $repoIdentity.id -or
    -not $repoIdentity.owner.id -or
    -not $repoIdentity.owner.login) {
    throw "GitHub did not return the exact numeric identity for '$Repository'."
}
$oidcCustomization = gh api "repos/$Repository/actions/oidc/customization/sub" | ConvertFrom-Json
if (-not $oidcCustomization.use_default -or
    -not $oidcCustomization.use_immutable_subject) {
    throw (
        'The repository must use GitHub default immutable OIDC subjects; ' +
        'customized and mutable subjects are not accepted.'
    )
}
$subjectPrefix = (
    "repo:$($repoIdentity.owner.login)@$($repoIdentity.owner.id)/" +
    "$($repoIdentity.name)@$($repoIdentity.id)"
)
if ($oidcCustomization.sub_claim_prefix -cne $subjectPrefix) {
    throw (
        "GitHub immutable OIDC prefix '$($oidcCustomization.sub_claim_prefix)' " +
        "does not match '$subjectPrefix'."
    )
}

$identityName = $infrastructure.outputs.workloadIdentityName.value
$resourceGroup = $infrastructure.resourceGroup
$issuer = 'https://token.actions.githubusercontent.com'
$subject = "$subjectPrefix`:environment:$Environment"
$audience = 'api://AzureADTokenExchange'
$encodedEnvironment = [Uri]::EscapeDataString($Environment)
$environmentUri = "repos/$Repository/environments/$encodedEnvironment"
$branchPoliciesUri = "$environmentUri/deployment-branch-policies"
$expectedEnvironmentSecretNames = @(
    'AZURE_CLIENT_ID'
    'AZURE_TENANT_ID'
    'CBA_APP_HOSTNAME_MASK'
    'CBA_APP_URL'
    'CBA_EXPECTED_OIDC_SUBJECT'
    'CBA_TEST_OBJECT_ID'
    'CBA_TEST_USERNAME'
    'KEY_VAULT_NAME'
    'KEY_VAULT_PRIVATE_ENDPOINT_IP'
    'RUNNER_SUBNET_CIDR'
)
$allowedBranchSet = @($AllowedBranches | Sort-Object -CaseSensitive -Unique)
if ($allowedBranchSet.Count -ne $AllowedBranches.Count) {
    throw 'Duplicate deployment branches are not allowed.'
}

function Write-GitHubState {
    param([Parameter(Mandatory)][Collections.IDictionary]$State)

    $operationId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$githubStatePath.$operationId.tmp"
    $backupPath = "$githubStatePath.$operationId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($State | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $githubStatePath) {
            [IO.File]::Replace($temporaryPath, $githubStatePath, $backupPath, $true)
        }
        else {
            [IO.File]::Move($temporaryPath, $githubStatePath)
        }
    }
    finally {
        foreach ($cleanupPath in @($temporaryPath, $backupPath)) {
            if (Test-Path -LiteralPath $cleanupPath) {
                Remove-Item -LiteralPath $cleanupPath -Force
            }
        }
    }
}

function Assert-ExactStringSet {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Actual,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actualValues = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)
    if (
        $actualValues.Count -ne $expectedValues.Count -or
        ($actualValues -join "`n") -cne ($expectedValues -join "`n")
    ) {
        throw "$Label does not match the exact expected set."
    }
}

$existingGithubState = if (Test-Path -LiteralPath $githubStatePath -PathType Leaf) {
    Get-Content -LiteralPath $githubStatePath -Raw | ConvertFrom-Json
}
else {
    $null
}
$legacyGithubState = $false
if ($existingGithubState) {
    $statePropertyNames = @($existingGithubState.PSObject.Properties.Name)
    $ownershipPropertyNames = @(
        'environmentCreated'
        'federatedCredentialCreated'
        'ownerId'
        'repositoryId'
        'status'
    )
    $ownershipPropertyCount = @($ownershipPropertyNames | Where-Object {
        $_ -in $statePropertyNames
    }).Count
    if ($ownershipPropertyCount -eq 0) {
        $legacyRequiredProperties = @(
            'allowedBranches'
            'environment'
            'environmentSecretNames'
            'federatedCredentialName'
            'immutableSubject'
            'issuer'
            'network'
            'repository'
            'subject'
            'subjectPrefix'
            'verifiedAt'
            'workloadClientId'
        )
        $missingLegacyProperties = @($legacyRequiredProperties | Where-Object {
            $_ -notin $statePropertyNames
        })
        Assert-ExactStringSet `
            -Actual @($existingGithubState.environmentSecretNames) `
            -Expected $expectedEnvironmentSecretNames `
            -Label 'Legacy GitHub environment secret names'
        if (
            $missingLegacyProperties.Count -ne 0 -or
            $existingGithubState.repository -cne $Repository -or
            $existingGithubState.environment -cne $Environment -or
            $existingGithubState.federatedCredentialName -cne $FederatedCredentialName -or
            $existingGithubState.issuer -cne $issuer -or
            $existingGithubState.subject -cne $subject -or
            $existingGithubState.subjectPrefix -cne $subjectPrefix -or
            $existingGithubState.workloadClientId -ne
                $infrastructure.outputs.workloadClientId.value -or
            $existingGithubState.immutableSubject -ne $true -or
            -not $existingGithubState.network -or
            $existingGithubState.network.runnerSubnetId -ne $runnerNetwork.runnerSubnetId -or
            $existingGithubState.network.privateEndpointIp -ne $runnerNetwork.privateEndpointIp
        ) {
            throw 'Legacy GitHub state does not match the exact current lab contract.'
        }
        $legacyGithubState = $true
    }
    elseif ($ownershipPropertyCount -ne $ownershipPropertyNames.Count) {
        throw 'Recorded GitHub state contains incomplete ownership metadata.'
    }
    elseif (
        $existingGithubState.status -notin @('provisioning', 'verified') -or
        $existingGithubState.repository -cne $Repository -or
        [string]$existingGithubState.repositoryId -cne [string]$repoIdentity.id -or
        [string]$existingGithubState.ownerId -cne [string]$repoIdentity.owner.id -or
        $existingGithubState.environment -cne $Environment -or
        $existingGithubState.federatedCredentialName -cne $FederatedCredentialName -or
        $existingGithubState.issuer -cne $issuer -or
        $existingGithubState.subject -cne $subject -or
        $existingGithubState.subjectPrefix -cne $subjectPrefix -or
        $existingGithubState.workloadClientId -ne
            $infrastructure.outputs.workloadClientId.value -or
        -not $existingGithubState.network -or
        $existingGithubState.network.runnerSubnetId -ne $runnerNetwork.runnerSubnetId -or
        $existingGithubState.network.privateEndpointIp -ne $runnerNetwork.privateEndpointIp -or
        (
            $existingGithubState.status -eq 'verified' -and
            (
                $existingGithubState.environmentCreated -ne $true -or
                $existingGithubState.federatedCredentialCreated -ne $true
            )
        )
    ) {
        throw 'Recorded GitHub state does not prove ownership of this exact repository environment.'
    }
}

$previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
$PSNativeCommandUseErrorActionPreference = $false
try {
    $environmentLookupOutput = @(
        & gh api --silent $environmentUri 2>&1
    )
    $environmentLookupExitCode = $LASTEXITCODE
}
finally {
    $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
}
$environmentExists = $environmentLookupExitCode -eq 0
if (-not $environmentExists -and (
    ($environmentLookupOutput | ForEach-Object { [string]$_ }) -join "`n"
) -notmatch '\(HTTP 404\)') {
    throw "GitHub environment lookup failed with exit code $environmentLookupExitCode."
}

$existingCredentials = @(
    az identity federated-credential list `
        --identity-name $identityName `
        --resource-group $resourceGroup `
        --output json | ConvertFrom-Json
)
$matchingCredentials = @($existingCredentials | Where-Object {
    $_.name -ceq $FederatedCredentialName
})
$unexpectedCredentials = @($existingCredentials | Where-Object {
    $_.name -cne $FederatedCredentialName
})
if ($unexpectedCredentials.Count -ne 0) {
    throw (
        'The workload identity has additional federated credentials outside the exact lab ' +
        'contract. No credential was modified.'
    )
}
if ($matchingCredentials.Count -ne 0) {
    Assert-ExactFederatedCredentialSet `
        -Credentials $existingCredentials `
        -ExpectedName $FederatedCredentialName `
        -ExpectedIssuer $issuer `
        -ExpectedSubject $subject `
        -ExpectedAudience $audience | Out-Null
}

if ($legacyGithubState) {
    if (-not $environmentExists -or $matchingCredentials.Count -ne 1) {
        throw 'Legacy GitHub state cannot be migrated because its exact live objects are missing.'
    }
    $legacyEnvironment = gh api $environmentUri | ConvertFrom-Json
    $legacyBranchPolicies = @(
        (gh api --paginate $branchPoliciesUri | ConvertFrom-Json).branch_policies
    )
    $recordedLegacyBranches = @(
        $existingGithubState.allowedBranches |
            Sort-Object -CaseSensitive -Unique
    )
    $liveLegacyBranches = @(
        $legacyBranchPolicies.name |
            Sort-Object -CaseSensitive -Unique
    )
    $liveLegacySecretNames = @(
        gh api `
            --paginate `
            "$environmentUri/secrets?per_page=100" `
            --jq '.secrets[].name' |
            Sort-Object -CaseSensitive -Unique
    )
    Assert-ExactStringSet `
        -Actual $liveLegacySecretNames `
        -Expected $expectedEnvironmentSecretNames `
        -Label 'Live legacy GitHub environment secret names'
    if (
        $recordedLegacyBranches.Count -ne
            @($existingGithubState.allowedBranches).Count -or
        $legacyBranchPolicies.Count -ne $recordedLegacyBranches.Count -or
        @($legacyBranchPolicies | Where-Object { $_.type -cne 'branch' }).Count -ne 0 -or
        (
            Compare-Object `
                -ReferenceObject $recordedLegacyBranches `
                -DifferenceObject $liveLegacyBranches `
                -CaseSensitive
        ) -or
        $legacyEnvironment.deployment_branch_policy.protected_branches -or
        -not $legacyEnvironment.deployment_branch_policy.custom_branch_policies
    ) {
        throw 'Legacy GitHub state does not match the exact live environment configuration.'
    }
    $migratedGithubState = [ordered]@{
        allowedBranches = @($recordedLegacyBranches)
        environment = $Environment
        environmentCreated = $true
        environmentSecretNames = @($expectedEnvironmentSecretNames)
        federatedCredentialCreated = $true
        federatedCredentialName = $FederatedCredentialName
        issuer = $issuer
        immutableSubject = $true
        network = $runnerNetwork
        ownerId = [string]$repoIdentity.owner.id
        repository = $Repository
        repositoryId = [string]$repoIdentity.id
        status = 'verified'
        subjectPrefix = $subjectPrefix
        subject = $subject
        verifiedAt = (Get-Date).ToString('o')
        workloadClientId = $infrastructure.outputs.workloadClientId.value
    }
    Write-GitHubState -State $migratedGithubState
    $existingGithubState = [pscustomobject]$migratedGithubState
}

if (-not $existingGithubState -and (
    $environmentExists -or $matchingCredentials.Count -ne 0
)) {
    throw (
        'The GitHub environment or federated credential already exists without exact local ' +
        'ownership state. Choose new disposable names.'
    )
}
if ($existingGithubState -and $existingGithubState.environmentCreated -eq $true -and
    -not $environmentExists) {
    throw 'The exact recorded GitHub environment no longer exists; refusing to replace it implicitly.'
}
if ($existingGithubState -and $existingGithubState.federatedCredentialCreated -eq $true -and
    $matchingCredentials.Count -eq 0) {
    throw 'The exact recorded federated credential no longer exists; refusing to replace it implicitly.'
}

$githubState = [ordered]@{
    allowedBranches = @($allowedBranchSet)
    environment = $Environment
    environmentCreated = if ($existingGithubState) {
        [bool]$existingGithubState.environmentCreated
    } else {
        $false
    }
    environmentSecretNames = @()
    federatedCredentialCreated = if ($existingGithubState) {
        [bool]$existingGithubState.federatedCredentialCreated
    } else {
        $false
    }
    federatedCredentialName = $FederatedCredentialName
    issuer = $issuer
    immutableSubject = [bool]$oidcCustomization.use_immutable_subject
    network = $runnerNetwork
    ownerId = [string]$repoIdentity.owner.id
    repository = $Repository
    repositoryId = [string]$repoIdentity.id
    status = 'provisioning'
    subjectPrefix = $subjectPrefix
    subject = $subject
    verifiedAt = $null
    workloadClientId = $infrastructure.outputs.workloadClientId.value
}
if (-not $existingGithubState) {
    Write-GitHubState -State $githubState
}

if ($matchingCredentials.Count -eq 0) {
    az identity federated-credential create `
        --name $FederatedCredentialName `
        --identity-name $identityName `
        --resource-group $resourceGroup `
        --issuer $issuer `
        --subject $subject `
        --audiences $audience `
        --output none
}
$githubState.federatedCredentialCreated = $true
Write-GitHubState -State $githubState

$environmentBody = @{
    deployment_branch_policy = @{
        custom_branch_policies = $true
        protected_branches = $false
    }
} | ConvertTo-Json -Depth 6
$environmentResponse = $environmentBody |
    gh api --method PUT $environmentUri --input - |
    ConvertFrom-Json
$githubState.environmentCreated = $true
Write-GitHubState -State $githubState

$existingBranchPolicies = @(
    (gh api --paginate $branchPoliciesUri | ConvertFrom-Json).branch_policies
)
foreach ($policy in $existingBranchPolicies) {
    if ($policy.type -cne 'branch' -or $allowedBranchSet -cnotcontains $policy.name) {
        gh api `
            --method DELETE `
            "$branchPoliciesUri/$($policy.id)" `
            --silent
    }
}
foreach ($branch in $allowedBranchSet) {
    if (@($existingBranchPolicies.name) -cnotcontains $branch) {
        gh api `
            --method POST `
            $branchPoliciesUri `
            --field "name=$branch" `
            --silent
    }
}

$environmentSecrets = [ordered]@{
    AZURE_CLIENT_ID = $infrastructure.outputs.workloadClientId.value
    AZURE_TENANT_ID = $infrastructure.tenantId
    CBA_APP_HOSTNAME_MASK = ([Uri]$application.appUrl).DnsSafeHost
    CBA_APP_URL = $application.appUrl
    CBA_EXPECTED_OIDC_SUBJECT = $subject
    CBA_TEST_OBJECT_ID = $entra.testUserId
    CBA_TEST_USERNAME = $entra.testUserUpn
    KEY_VAULT_NAME = $infrastructure.outputs.runnerVaultName.value
    KEY_VAULT_PRIVATE_ENDPOINT_IP = $runnerNetwork.privateEndpointIp
    RUNNER_SUBNET_CIDR = $runnerNetwork.runnerSubnetCidr
}
foreach ($entry in $environmentSecrets.GetEnumerator()) {
    gh secret set `
        $entry.Key `
        --repo $Repository `
        --env $Environment `
        --body ([string]$entry.Value)
}
$verifiedSecretNames = @(
    gh api `
        --paginate `
        "$environmentUri/secrets?per_page=100" `
        --jq '.secrets[].name'
)
Assert-ExactStringSet `
    -Actual $verifiedSecretNames `
    -Expected @($environmentSecrets.Keys) `
    -Label 'GitHub environment secret names'

$legacyEnvironmentVariableNames = @(
    'AZURE_CLIENT_ID',
    'AZURE_SUBSCRIPTION_ID',
    'AZURE_TENANT_ID',
    'CBA_APP_HOSTNAME_MASK',
    'CBA_APP_URL',
    'CBA_CERTAUTH_ORIGIN',
    'CBA_EXPECTED_OIDC_SUBJECT',
    'CBA_PFX_PASSPHRASE_SECRET_NAME',
    'CBA_PFX_SECRET_NAME',
    'CBA_TEST_OBJECT_ID',
    'CBA_TEST_USERNAME',
    'KEY_VAULT_NAME',
    'KEY_VAULT_PRIVATE_ENDPOINT_IP',
    'RUNNER_OUTBOUND_IP',
    'RUNNER_SUBNET_CIDR'
)
$existingEnvironmentVariableNames = @(
    gh variable list `
        --repo $Repository `
        --env $Environment `
        --json name |
        ConvertFrom-Json |
        ForEach-Object { $_.name }
)
foreach ($variableName in $legacyEnvironmentVariableNames) {
    if ($existingEnvironmentVariableNames -ccontains $variableName) {
        gh variable delete `
            $variableName `
            --repo $Repository `
            --env $Environment
    }
}

$verifiedCredentials = @(
    az identity federated-credential list `
    --identity-name $identityName `
    --resource-group $resourceGroup `
    --output json | ConvertFrom-Json
)
Assert-ExactFederatedCredentialSet `
    -Credentials $verifiedCredentials `
    -ExpectedName $FederatedCredentialName `
    -ExpectedIssuer $issuer `
    -ExpectedSubject $subject `
    -ExpectedAudience $audience | Out-Null

$verifiedEnvironment = gh api $environmentUri | ConvertFrom-Json
$verifiedBranchPolicies = @(
    (gh api --paginate $branchPoliciesUri | ConvertFrom-Json).branch_policies
)
if ($verifiedBranchPolicies.Count -ne $allowedBranchSet.Count) {
    throw 'GitHub environment has unexpected deployment branch policies.'
}
foreach ($branch in $allowedBranchSet) {
    if (@($verifiedBranchPolicies.name) -cnotcontains $branch) {
        throw "GitHub environment does not allow required branch '$branch'."
    }
}
if (@($verifiedBranchPolicies | Where-Object { $_.type -cne 'branch' }).Count -ne 0) {
    throw 'GitHub environment contains a non-branch deployment policy.'
}
if ($verifiedEnvironment.deployment_branch_policy.protected_branches -or
    -not $verifiedEnvironment.deployment_branch_policy.custom_branch_policies) {
    throw 'GitHub environment branch protection is not configured for explicit custom branches.'
}

$githubState.environmentSecretNames = @($environmentSecrets.Keys)
$githubState.status = 'verified'
$githubState.verifiedAt = (Get-Date).ToString('o')
Write-GitHubState -State $githubState

Write-Host "GitHub environment '$Environment' is restricted to: $($AllowedBranches -join ', ')"
Write-Host (
    "Configured $($environmentSecrets.Count) encrypted GitHub environment secrets. " +
    'The certificate and passphrase remain only in Key Vault.'
)
