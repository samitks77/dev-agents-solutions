[CmdletBinding()]
param(
    [string]$Repository = 'samitks77/dev-agents-solutions',
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
    -not $repoIdentity.owner.id) {
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

$existingCredentials = @(
    az identity federated-credential list `
        --identity-name $identityName `
        --resource-group $resourceGroup `
        --output json | ConvertFrom-Json
)
$matchingCredentials = @($existingCredentials | Where-Object { $_.name -eq $FederatedCredentialName })
if ($matchingCredentials.Count -gt 1) {
    throw "More than one federated credential is named '$FederatedCredentialName'."
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
} else {
    az identity federated-credential update `
        --name $FederatedCredentialName `
        --identity-name $identityName `
        --resource-group $resourceGroup `
        --issuer $issuer `
        --subject $subject `
        --audiences $audience `
        --output none
}

$encodedEnvironment = [Uri]::EscapeDataString($Environment)
$environmentUri = "repos/$Repository/environments/$encodedEnvironment"
$environmentBody = @{
    deployment_branch_policy = @{
        custom_branch_policies = $true
        protected_branches = $false
    }
} | ConvertTo-Json -Depth 6
$environmentResponse = $environmentBody |
    gh api --method PUT $environmentUri --input - |
    ConvertFrom-Json

$branchPoliciesUri = "$environmentUri/deployment-branch-policies"
$existingBranchPolicies = @(
    (gh api --paginate $branchPoliciesUri | ConvertFrom-Json).branch_policies
)
$allowedBranchSet = @($AllowedBranches | Sort-Object -CaseSensitive -Unique)
if ($allowedBranchSet.Count -ne $AllowedBranches.Count) {
    throw 'Duplicate deployment branches are not allowed.'
}
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

$environmentVariables = [ordered]@{
    AZURE_CLIENT_ID = $infrastructure.outputs.workloadClientId.value
    AZURE_SUBSCRIPTION_ID = $infrastructure.subscriptionId
    AZURE_TENANT_ID = $infrastructure.tenantId
    CBA_APP_URL = $application.appUrl
    CBA_CERTAUTH_ORIGIN = 'https://certauth.login.microsoftonline.com'
    CBA_EXPECTED_OIDC_SUBJECT = $subject
    CBA_PFX_PASSPHRASE_SECRET_NAME = 'cba-test-user-pfx-passphrase'
    CBA_PFX_SECRET_NAME = 'cba-test-user-pfx'
    CBA_TEST_OBJECT_ID = $entra.testUserId
    CBA_TEST_USERNAME = $entra.testUserUpn
    KEY_VAULT_NAME = $infrastructure.outputs.runnerVaultName.value
    KEY_VAULT_PRIVATE_ENDPOINT_IP = $runnerNetwork.privateEndpointIp
    RUNNER_OUTBOUND_IP = $runnerNetwork.runnerOutboundIp
    RUNNER_SUBNET_CIDR = $runnerNetwork.runnerSubnetCidr
}
foreach ($entry in $environmentVariables.GetEnumerator()) {
    gh variable set `
        $entry.Key `
        --repo $Repository `
        --env $Environment `
        --body ([string]$entry.Value)
}

$verifiedCredential = az identity federated-credential show `
    --name $FederatedCredentialName `
    --identity-name $identityName `
    --resource-group $resourceGroup `
    --output json | ConvertFrom-Json
if ($verifiedCredential.issuer -ne $issuer -or
    $verifiedCredential.subject -ne $subject -or
    @($verifiedCredential.audiences).Count -ne 1 -or
    $verifiedCredential.audiences[0] -ne $audience) {
    throw 'Federated credential read-back verification failed.'
}

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

$githubState = [ordered]@{
    allowedBranches = @($allowedBranchSet)
    environment = $Environment
    federatedCredentialName = $FederatedCredentialName
    issuer = $issuer
    immutableSubject = [bool]$oidcCustomization.use_immutable_subject
    network = $runnerNetwork
    repository = $Repository
    subjectPrefix = $subjectPrefix
    subject = $subject
    verifiedAt = (Get-Date).ToString('o')
    workloadClientId = $infrastructure.outputs.workloadClientId.value
}
$githubState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $githubStatePath -Encoding utf8NoBOM

Write-Host "GitHub environment '$Environment' is restricted to: $($AllowedBranches -join ', ')"
Write-Host "Azure federated subject: $subject"
Write-Host 'No GitHub secret was created.'
