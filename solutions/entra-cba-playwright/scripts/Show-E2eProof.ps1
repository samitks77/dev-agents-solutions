[CmdletBinding()]
param(
    [long]$ExpectedRunId,
    [string]$ExpectedHeadSha,
    [guid]$ExpectedPositiveCorrelationId,
    [guid]$ExpectedNegativeCorrelationId,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$labRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $labRoot '.artifacts\showcase'
}

$stateDirectory = Join-Path $labRoot '.lab-state'
. (Join-Path $PSScriptRoot 'Proof-Set.ps1')
. (Join-Path $PSScriptRoot 'Runner-Network.ps1')
. (Join-Path $PSScriptRoot 'Workflow-Privacy.ps1')
$paths = [ordered]@{
    application = Join-Path $stateDirectory 'application.json'
    conditionalAccess = Join-Path $stateDirectory 'conditional-access.json'
    headed = Join-Path $stateDirectory 'headed-feasibility.json'
    headless = Join-Path $stateDirectory 'headless-reliability.json'
    isolation = Join-Path $stateDirectory 'conditional-access-isolation.json'
    entra = Join-Path $stateDirectory 'entra.json'
    github = Join-Path $stateDirectory 'github.json'
    infrastructure = Join-Path $stateDirectory 'infrastructure.json'
    negative = Join-Path $stateDirectory 'auth-strength-negative.json'
    positive = Join-Path $stateDirectory 'auth-strength-positive.json'
    runner = Join-Path $stateDirectory 'runner.json'
    session = Join-Path $stateDirectory 'session-reuse.json'
    wrongOrigin = Join-Path $stateDirectory 'wrong-origin-control.json'
}

foreach ($path in $paths.Values) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required proof state '$path' does not exist."
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path)

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        throw "Proof state '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

function Invoke-NativeJson {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    $output = & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw (
            "Command '$FilePath $($ArgumentList -join ' ')' failed with " +
            "exit code $LASTEXITCODE."
        )
    }
    $json = $output -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($json)) {
        throw "Command '$FilePath $($ArgumentList -join ' ')' returned no JSON."
    }
    try {
        return $json | ConvertFrom-Json
    } catch {
        throw (
            "Command '$FilePath $($ArgumentList -join ' ')' returned invalid " +
            "JSON: $($_.Exception.Message)"
        )
    }
}

function Test-ExactStringSet {
    param(
        [AllowEmptyCollection()][object[]]$Actual,
        [AllowEmptyCollection()][object[]]$Expected
    )

    $actualValues = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ($actualValues.Count -ne $expectedValues.Count) {
        return $false
    }
    foreach ($value in $actualValues) {
        if ($expectedValues -cnotcontains $value) {
            return $false
        }
    }
    return $true
}

$checks = [Collections.Generic.List[object]]::new()
function Add-ProofCheck {
    param(
        [Parameter(Mandatory)][string]$Stage,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Evidence
    )

    $checks.Add([pscustomobject][ordered]@{
        stage = $Stage
        name = $Name
        result = if ($Condition) { 'PASS' } else { 'FAIL' }
        source = $Source
        evidence = $Evidence
    })
}

function ConvertTo-HtmlText {
    param([AllowEmptyString()][string]$Value)

    return [Net.WebUtility]::HtmlEncode($Value)
}

Get-Command gh -ErrorAction Stop | Out-Null
Get-Command az -ErrorAction Stop | Out-Null

$application = Read-JsonFile -Path $paths.application
$conditionalAccess = Read-JsonFile -Path $paths.conditionalAccess
$entra = Read-JsonFile -Path $paths.entra
$github = Read-JsonFile -Path $paths.github
$headed = Read-JsonFile -Path $paths.headed
$headless = Read-JsonFile -Path $paths.headless
$infrastructure = Read-JsonFile -Path $paths.infrastructure
$isolation = Read-JsonFile -Path $paths.isolation
$negative = Read-JsonFile -Path $paths.negative
$positive = Read-JsonFile -Path $paths.positive
$runner = Read-JsonFile -Path $paths.runner
$session = Read-JsonFile -Path $paths.session
$wrongOrigin = Read-JsonFile -Path $paths.wrongOrigin

$evidenceDirectory = Join-Path $labRoot (
    ".artifacts\ci\$($runner.workflowRunId)"
)
$identityPath = Join-Path $evidenceDirectory 'cba-feasibility.json'
$networkPath = Join-Path $evidenceDirectory 'runner-network.json'
foreach ($path in @($identityPath, $networkPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required bounded receipt '$path' does not exist."
    }
}
$identity = Read-JsonFile -Path $identityPath
$network = Read-JsonFile -Path $networkPath
$expectedIdentitySha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes(
            ([ordered]@{
                appUrl = $application.appUrl
                objectId = $entra.testUserId
                tenantId = $entra.tenantId
                username = $entra.testUserUpn
            } | ConvertTo-Json -Compress)
        )
    )
).ToLowerInvariant()
if ($ExpectedRunId -eq 0) {
    $ExpectedRunId = [long]$runner.workflowRunId
}
if ([string]::IsNullOrWhiteSpace($ExpectedHeadSha)) {
    $ExpectedHeadSha = [string]$identity.githubSha
}
if (-not $PSBoundParameters.ContainsKey('ExpectedPositiveCorrelationId') -or
    $ExpectedPositiveCorrelationId -eq [guid]::Empty) {
    $ExpectedPositiveCorrelationId = [guid]$positive.correlationId
}
if (-not $PSBoundParameters.ContainsKey('ExpectedNegativeCorrelationId') -or
    $ExpectedNegativeCorrelationId -eq [guid]::Empty) {
    $ExpectedNegativeCorrelationId = [guid]$negative.correlationId
}

$run = Invoke-NativeJson -FilePath 'gh' -ArgumentList @(
    'run',
    'view',
    [string]$ExpectedRunId,
    '--repo',
    [string]$runner.repository,
    '--json',
    'databaseId,status,conclusion,headSha,headBranch,event,workflowName,url,jobs'
)
$calculatedProofSetId = Get-E2eProofSetId `
    -Repository $runner.repository `
    -RunId ([long]$run.databaseId) `
    -HeadSha $run.headSha `
    -WorkflowFile $runner.workflowFile `
    -OidcSubject $github.subject
Add-ProofCheck `
    -Stage 'Cross-gate binding' `
    -Name 'Cloud, browser, policy and restoration evidence share one proof set' `
    -Condition (
        $runner.proofSetId -ceq $calculatedProofSetId -and
        $positive.proofSetId -ceq $calculatedProofSetId -and
        $negative.proofSetId -ceq $calculatedProofSetId -and
        $isolation.proofSetId -ceq $calculatedProofSetId -and
        $headed.proofSetId -ceq $calculatedProofSetId -and
        $headless.proofSetId -ceq $calculatedProofSetId -and
        $session.proofSetId -ceq $calculatedProofSetId -and
        $wrongOrigin.proofSetId -ceq $calculatedProofSetId
    ) `
    -Source 'Deterministic SHA-256 proof-set binding' `
    -Evidence "proofSetId=$calculatedProofSetId"

Add-ProofCheck `
    -Stage 'GitHub control plane' `
    -Name 'Exact workflow run completed successfully' `
    -Condition (
        $run.databaseId -eq $ExpectedRunId -and
        $run.status -eq 'completed' -and
        $run.conclusion -eq 'success' -and
        $run.workflowName -eq 'Entra CBA Playwright POC'
    ) `
    -Source 'Live GitHub API' `
    -Evidence "run=$($run.databaseId); status=$($run.status); conclusion=$($run.conclusion)"
Add-ProofCheck `
    -Stage 'GitHub control plane' `
    -Name 'Tested branch and commit are exact' `
    -Condition (
        $run.headSha -eq $ExpectedHeadSha -and
        $run.headBranch -eq $runner.ref -and
        $run.event -in @('push', 'workflow_dispatch')
    ) `
    -Source 'Live GitHub API' `
    -Evidence "branch=$($run.headBranch); sha=$($run.headSha); event=$($run.event)"

$job = @($run.jobs | Where-Object { $_.name -eq 'Verify Entra CBA' })
Add-ProofCheck `
    -Stage 'GitHub control plane' `
    -Name 'One exact verification job passed' `
    -Condition (
        $job.Count -eq 1 -and
        $job[0].status -eq 'completed' -and
        $job[0].conclusion -eq 'success'
    ) `
    -Source 'Live GitHub API' `
    -Evidence "jobs=$($job.Count); conclusion=$($job[0].conclusion)"

$requiredStepNames = @(
    'Validate the dispatch identifier',
    'Check out the tested revision',
    'Verify private Key Vault DNS',
    'Exchange GitHub OIDC and retrieve CBA credentials',
    'Validate the retrieved PFX',
    'Type-check the POC',
    'Run the headless CBA feasibility test',
    'Validate bounded test evidence',
    'Upload bounded test evidence',
    'Remove runtime credentials'
)
foreach ($stepName in $requiredStepNames) {
    $step = @($job[0].steps | Where-Object { $_.name -eq $stepName })
    Add-ProofCheck `
        -Stage 'GitHub job execution' `
        -Name $stepName `
        -Condition (
            $step.Count -eq 1 -and
            $step[0].status -eq 'completed' -and
            $step[0].conclusion -eq 'success'
        ) `
        -Source 'Live GitHub API' `
        -Evidence "status=$($step[0].status); conclusion=$($step[0].conclusion)"
}

$workflowLogProtectedValues = Get-WorkflowLogProtectedValues `
    -Application $application `
    -Entra $entra `
    -GitHub $github `
    -Infrastructure $infrastructure `
    -RunnerNetwork $runner.network
$runnerPrivateIpv4 = [string]$runner.runnerPrivateIpv4
if ($runnerPrivateIpv4 -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$' -or
    -not (Test-Ipv4AddressInCidr `
        -Address $runnerPrivateIpv4 `
        -Cidr ([string]$runner.network.runnerSubnetCidr)) -or
    (Get-TextSha256 -Text (
        ConvertTo-Json -InputObject @($runnerPrivateIpv4) -Compress
    )) -cne $runner.runnerPrivateIpv4InExpectedSubnetSha256) {
    throw 'Ignored runner state does not preserve the exact verified transient ACI address.'
}
$workflowLogProtectedValues['ACI runner private IP'] = $runnerPrivateIpv4
$workflowLogPrivacy = Test-WorkflowLogPrivacy `
    -Repository $runner.repository `
    -RunId $ExpectedRunId `
    -ProtectedValues $workflowLogProtectedValues
Add-ProofCheck `
    -Stage 'Public log privacy' `
    -Name 'GitHub job log contains no exact or encoded lab deployment values' `
    -Condition (
        $runner.workflowLogPrivacyVerified -eq $true -and
        $runner.workflowLogSha256 -ceq $workflowLogPrivacy.logSha256 -and
        [int]$runner.workflowLogProtectedValueCount -eq
            [int]$workflowLogPrivacy.protectedValueCount -and
        [int]$runner.workflowLogVariantCount -eq
            [int]$workflowLogPrivacy.variantCount
    ) `
    -Source 'Live GitHub log replay against ignored local state' `
    -Evidence (
        "protectedValues=$($workflowLogPrivacy.protectedValueCount); " +
        "variants=$($workflowLogPrivacy.variantCount); " +
        "logSha256=$($workflowLogPrivacy.logSha256)"
    )

$identityHash = (
    Get-FileHash -LiteralPath $identityPath -Algorithm SHA256
).Hash.ToLowerInvariant()
$networkHash = (
    Get-FileHash -LiteralPath $networkPath -Algorithm SHA256
).Hash.ToLowerInvariant()
Add-ProofCheck `
    -Stage 'Bounded evidence' `
    -Name 'Identity receipt SHA-256 matches the launcher receipt' `
    -Condition ($identityHash -ceq $runner.identityReceiptSha256) `
    -Source 'Local cryptographic replay' `
    -Evidence "sha256=$identityHash"
Add-ProofCheck `
    -Stage 'Bounded evidence' `
    -Name 'Network receipt SHA-256 matches the launcher receipt' `
    -Condition ($networkHash -ceq $runner.networkReceiptSha256) `
    -Source 'Local cryptographic replay' `
    -Evidence "sha256=$networkHash"
Add-ProofCheck `
    -Stage 'Playwright identity' `
    -Name 'Exact identity commitment, run, and SHA were verified' `
    -Condition (
        [int]$identity.schemaVersion -eq 3 -and
        [long]$identity.githubRunId -eq $ExpectedRunId -and
        $identity.githubSha -eq $ExpectedHeadSha -and
        $identity.identitySha256 -ceq $expectedIdentitySha256 -and
        $identity.verificationIdSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.verificationId)
        )
    ) `
    -Source 'Re-hashed Playwright receipt' `
    -Evidence "identitySha256=$($identity.identitySha256)"

$localControls = @(
    @{
        name = 'Headed Chromium rendered the exact identity'
        receipt = $headed
        scenario = 'headed-feasibility'
        assertions = @('exact-identity-rendered-in-headed-chromium')
        repeat = 1
    },
    @{
        name = 'Five independent headless sessions passed'
        receipt = $headless
        scenario = 'headless-reliability'
        assertions = @('all-independent-headless-runs-passed')
        repeat = 5
    },
    @{
        name = 'Wrong-origin certificate isolation passed'
        receipt = $wrongOrigin
        scenario = 'wrong-origin'
        assertions = @('unapproved-origin-rejected', 'no-certificate-detected')
        repeat = 1
    },
    @{
        name = 'Authenticated session reused without a new CBA request'
        receipt = $session
        scenario = 'session-reuse'
        assertions = @(
            'exact-identity-reused',
            'certificate-authentication-request-count-zero'
        )
        repeat = 1
    }
)
foreach ($control in $localControls) {
    $testPath = Join-Path $labRoot "tests\$($control.receipt.project).spec.ts"
    Add-ProofCheck `
        -Stage 'Local browser controls' `
        -Name $control.name `
        -Condition (
            [int]$control.receipt.schemaVersion -eq 1 -and
            $control.receipt.scenario -eq $control.scenario -and
            $control.receipt.conclusion -eq 'passed' -and
            $control.receipt.sourceCommit -eq $ExpectedHeadSha -and
            $control.receipt.identitySha256 -ceq $expectedIdentitySha256 -and
            [int]$control.receipt.repeatRequested -eq $control.repeat -and
            [int]$control.receipt.successfulRuns -eq $control.repeat -and
            (Test-ExactStringSet `
                -Actual @($control.receipt.assertions) `
                -Expected $control.assertions) -and
            (Test-Path -LiteralPath $testPath -PathType Leaf) -and
            $control.receipt.testFileSha256 -ceq (
                Get-FileHash -LiteralPath $testPath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        ) `
        -Source 'Bounded local Playwright receipt' `
        -Evidence (
            "scenario=$($control.receipt.scenario); " +
            "runs=$($control.receipt.successfulRuns); " +
            "testSha256=$($control.receipt.testFileSha256)"
        )
}
Add-ProofCheck `
    -Stage 'Private credential path' `
    -Name 'Runner resolved and read Key Vault only at the private IP' `
    -Condition (
        [int]$network.schemaVersion -eq 2 -and
        $network.azure.keyVaultRead -eq 'succeeded' -and
        $network.azure.keyVaultHostSha256 -ceq (
            Get-TextSha256 -Text "$($runner.network.keyVaultName).vault.azure.net"
        ) -and
        $network.azure.privateEndpointIpSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.network.privateEndpointIp)
        ) -and
        $network.azure.runnerSubnetCidrSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.network.runnerSubnetCidr)
        ) -and
        [int]$network.azure.resolvedVaultIpv4AddressCount -eq 1 -and
        $network.azure.resolvedVaultIpv4AddressSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.network.privateEndpointIp)
        )
    ) `
    -Source 'Re-hashed runner receipt' `
    -Evidence (
        "vaultRead=$($network.azure.keyVaultRead); " +
        "endpointSha256=$($network.azure.privateEndpointIpSha256)"
    )
Add-ProofCheck `
    -Stage 'GitHub workload identity' `
    -Name 'OIDC issuer, audience, subject, repository, run, and SHA are exact' `
    -Condition (
        $network.github.oidcIssuer -eq 'https://token.actions.githubusercontent.com' -and
        $network.github.oidcAudience -eq 'api://AzureADTokenExchange' -and
        $network.github.oidcSubjectSha256 -ceq (
            Get-TextSha256 -Text ([string]$github.subject)
        ) -and
        $network.github.repository -eq $runner.repository -and
        [long]$network.github.runId -eq $ExpectedRunId -and
        $network.github.sha -eq $ExpectedHeadSha -and
        $network.verificationIdSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.verificationId)
        )
    ) `
    -Source 'Re-hashed runner receipt' `
    -Evidence (
        "issuer=$($network.github.oidcIssuer); " +
        "subjectSha256=$($network.github.oidcSubjectSha256)"
    )
Add-ProofCheck `
    -Stage 'Ephemeral runner identity' `
    -Name 'ACI runner name, label, subnet, and operating system are exact' `
    -Condition (
        $network.runner.environment -eq 'self-hosted' -and
        $network.runner.nameSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.runnerName)
        ) -and
        $network.runner.labelSha256 -ceq (
            Get-TextSha256 -Text ([string]$runner.label)
        ) -and
        $network.runner.os -eq 'Linux' -and
        $network.runner.architecture -eq 'X64' -and
        [int]$network.runner.privateIpv4AddressCount -ge 1 -and
        [int]$network.runner.privateIpv4InExpectedSubnetCount -eq 1 -and
        $network.runner.privateIpv4InExpectedSubnetSha256 -ceq
            $runner.runnerPrivateIpv4InExpectedSubnetSha256
    ) `
    -Source 'Re-hashed runner receipt' `
    -Evidence (
        "nameSha256=$($network.runner.nameSha256); " +
        "labelSha256=$($network.runner.labelSha256); " +
        "privateIpv4Commitment=$($network.runner.privateIpv4InExpectedSubnetSha256)"
    )

$subscriptionId = [string]$infrastructure.subscriptionId
$resourceGroup = [string]$infrastructure.resourceGroup
$vaultName = [string]$infrastructure.outputs.runnerVaultName.value
$vnetName = [string]$infrastructure.outputs.virtualNetworkName.value
$privateEndpointName = [string](
    $infrastructure.outputs.keyVaultPrivateEndpointName.value
)
$account = Invoke-NativeJson -FilePath 'az' -ArgumentList @(
    'account', 'show', '--output', 'json'
)
$vault = Invoke-NativeJson -FilePath 'az' -ArgumentList @(
    'keyvault', 'show',
    '--subscription', $subscriptionId,
    '--resource-group', $resourceGroup,
    '--name', $vaultName,
    '--output', 'json'
)
$privateEndpoint = Invoke-NativeJson -FilePath 'az' -ArgumentList @(
    'network', 'private-endpoint', 'show',
    '--subscription', $subscriptionId,
    '--resource-group', $resourceGroup,
    '--name', $privateEndpointName,
    '--output', 'json'
)
$runnerSubnet = Invoke-NativeJson -FilePath 'az' -ArgumentList @(
    'network', 'vnet', 'subnet', 'show',
    '--subscription', $subscriptionId,
    '--resource-group', $resourceGroup,
    '--vnet-name', $vnetName,
    '--name', 'snet-github-runner',
    '--output', 'json'
)
$dnsRecord = Invoke-NativeJson -FilePath 'az' -ArgumentList @(
    'network', 'private-dns', 'record-set', 'a', 'show',
    '--subscription', $subscriptionId,
    '--resource-group', $resourceGroup,
    '--zone-name', 'privatelink.vaultcore.azure.net',
    '--name', $vaultName,
    '--output', 'json'
)
$containers = @(Invoke-NativeJson -FilePath 'az' -ArgumentList @(
    'container', 'list',
    '--subscription', $subscriptionId,
    '--resource-group', $resourceGroup,
    '--output', 'json'
))
$registeredRunners = Invoke-NativeJson -FilePath 'gh' -ArgumentList @(
    'api',
    "repos/$($runner.repository)/actions/runners?per_page=100"
)

Add-ProofCheck `
    -Stage 'Azure control plane' `
    -Name 'Azure CLI is on the exact subscription and tenant' `
    -Condition (
        $account.id -eq $subscriptionId -and
        $account.tenantId -eq $infrastructure.tenantId
    ) `
    -Source 'Live Azure API' `
    -Evidence "subscription=$($account.id); tenant=$($account.tenantId)"
Add-ProofCheck `
    -Stage 'Azure private network' `
    -Name 'Key Vault public access remains disabled and default action is deny' `
    -Condition (
        $vault.properties.publicNetworkAccess -eq 'Disabled' -and
        $vault.properties.networkAcls.defaultAction -eq 'Deny'
    ) `
    -Source 'Live Azure API' `
    -Evidence (
        "publicNetworkAccess=$($vault.properties.publicNetworkAccess); " +
        "defaultAction=$($vault.properties.networkAcls.defaultAction)"
    )
$privateConnections = @($privateEndpoint.privateLinkServiceConnections)
Add-ProofCheck `
    -Stage 'Azure private network' `
    -Name 'Key Vault Private Endpoint is succeeded and approved' `
    -Condition (
        $privateEndpoint.provisioningState -eq 'Succeeded' -and
        $privateConnections.Count -eq 1 -and
        $privateConnections[0].privateLinkServiceConnectionState.status -eq
            'Approved' -and
        $privateConnections[0].privateLinkServiceId -eq $runner.network.keyVaultId
    ) `
    -Source 'Live Azure API' `
    -Evidence (
        "endpoint=$($privateEndpoint.name); " +
        "status=$($privateConnections[0].privateLinkServiceConnectionState.status)"
    )
Add-ProofCheck `
    -Stage 'Azure private network' `
    -Name 'Private DNS A record maps the vault to the exact private IP' `
    -Condition (
        Test-ExactStringSet `
            -Actual @($dnsRecord.aRecords.ipv4Address) `
            -Expected @($runner.network.privateEndpointIp)
    ) `
    -Source 'Live Azure API' `
    -Evidence "vault=$vaultName; ip=$(@($dnsRecord.aRecords.ipv4Address) -join ',')"
Add-ProofCheck `
    -Stage 'Azure runner network' `
    -Name 'Runner subnet remains delegated to ACI and attached to NAT' `
    -Condition (
        $runnerSubnet.addressPrefix -eq $runner.network.runnerSubnetCidr -and
        @($runnerSubnet.delegations.serviceName) -contains
            'Microsoft.ContainerInstance/containerGroups' -and
        $runnerSubnet.natGateway.id -eq $runner.network.runnerNatGatewayId
    ) `
    -Source 'Live Azure API' `
    -Evidence (
        "subnet=$($runnerSubnet.addressPrefix); " +
        "delegation=$(@($runnerSubnet.delegations.serviceName) -join ','); " +
        "nat=$($runnerSubnet.natGateway.id)"
    )

Add-ProofCheck `
    -Stage 'Conditional Access positive' `
    -Name 'MFA-classified certificate satisfied the exact lab policy' `
    -Condition (
        [guid]$positive.correlationId -eq $ExpectedPositiveCorrelationId -and
        $positive.scenario -eq 'positive' -and
        $positive.authenticationMethod -eq 'Certificate-based authentication' -and
        $positive.certificateAuthenticationLevel -eq
            'multiFactorAuthentication' -and
        $positive.certificateStepSucceeded -eq $true -and
        $positive.errorCode -eq 0 -and
        $positive.policyResult -eq 'success' -and
        $positive.modernPkiStoreUsed -eq $true
    ) `
    -Source 'Sanitized Entra sign-in receipt' `
    -Evidence (
        "correlation=$($positive.correlationId); policy=$($positive.policyId); " +
        "result=$($positive.policyResult); error=$($positive.errorCode)"
    )
$expectedManagedPolicyIds = @($negative.isolatedManagedPolicyIds)
Add-ProofCheck `
    -Stage 'Conditional Access negative' `
    -Name 'SFA-classified certificate failed only the exact lab policy' `
    -Condition (
        [guid]$negative.correlationId -eq $ExpectedNegativeCorrelationId -and
        $negative.scenario -eq 'negative' -and
        $negative.authenticationMethod -eq 'Certificate-based authentication' -and
        $negative.certificateAuthenticationLevel -eq
            'singleFactorAuthentication' -and
        $negative.certificateStepSucceeded -eq $false -and
        $negative.errorCode -eq 500187 -and
        $negative.policyId -eq $positive.policyId -and
        $negative.policyResult -eq 'failure' -and
        $negative.modernPkiStoreUsed -eq $true -and
        $expectedManagedPolicyIds.Count -gt 0 -and
        (Test-ExactStringSet `
            -Actual @($negative.isolatedManagedPolicyIds) `
            -Expected $expectedManagedPolicyIds)
    ) `
    -Source 'Sanitized Entra sign-in receipt' `
    -Evidence (
        "correlation=$($negative.correlationId); policy=$($negative.policyId); " +
        "result=$($negative.policyResult); error=$($negative.errorCode)"
    )
Add-ProofCheck `
    -Stage 'Conditional Access restoration' `
    -Name 'Lab policy is recorded report-only after the proof' `
    -Condition (
        $conditionalAccess.policyId -eq $negative.policyId -and
        $conditionalAccess.policyState -eq
            'enabledForReportingButNotEnforced'
    ) `
    -Source 'Post-transaction read-back receipt' `
    -Evidence (
        "policy=$($conditionalAccess.policyId); " +
        "state=$($conditionalAccess.policyState)"
    )
Add-ProofCheck `
    -Stage 'Conditional Access restoration' `
    -Name 'Every temporarily isolated managed policy was restored' `
    -Condition (
        $isolation.schemaVersion -eq 3 -and
        $isolation.status -eq 'restored' -and
        (Test-ExactStringSet `
            -Actual @($isolation.appliedPolicyIds) `
            -Expected $expectedManagedPolicyIds) -and
        (Test-ExactStringSet `
            -Actual @($isolation.restoredPolicyIds) `
            -Expected $expectedManagedPolicyIds)
    ) `
    -Source 'Atomic isolation journal' `
    -Evidence (
        "status=$($isolation.status); restoredAt=$($isolation.restoredAt); " +
        "policies=$(@($isolation.restoredPolicyIds) -join ',')"
    )

$matchingContainers = @(
    $containers | Where-Object { $_.name -eq $runner.containerName }
)
$matchingRunners = @(
    $registeredRunners.runners | Where-Object {
        $_.name -eq $runner.runnerName -or
        @($_.labels.name) -contains $runner.label
    }
)
$artifactResponse = Invoke-NativeJson -FilePath 'gh' -ArgumentList @(
    'api',
    "repos/$($runner.repository)/actions/runs/$ExpectedRunId/artifacts"
)
$matchingArtifacts = @($artifactResponse.artifacts | Where-Object {
    $_.name -like 'entra-cba-playwright-*'
})
Add-ProofCheck `
    -Stage 'Public artifact privacy' `
    -Name 'Transient GitHub evidence artifact was deleted after verified download' `
    -Condition (
        $runner.evidenceArtifactDeleted -eq $true -and
        $matchingArtifacts.Count -eq 0
    ) `
    -Source 'Live GitHub API' `
    -Evidence "matchingArtifacts=$($matchingArtifacts.Count); localReceiptsRetained=true"
Add-ProofCheck `
    -Stage 'Live cleanup' `
    -Name 'Ephemeral ACI container no longer exists' `
    -Condition ($matchingContainers.Count -eq 0) `
    -Source 'Live Azure API' `
    -Evidence "container=$($runner.containerName); matches=$($matchingContainers.Count)"
Add-ProofCheck `
    -Stage 'Live cleanup' `
    -Name 'Ephemeral GitHub runner is deregistered' `
    -Condition ($matchingRunners.Count -eq 0) `
    -Source 'Live GitHub API' `
    -Evidence "runner=$($runner.runnerName); matches=$($matchingRunners.Count)"

$failedChecks = @($checks | Where-Object { $_.result -eq 'FAIL' })
$overallResult = if ($failedChecks.Count -eq 0) { 'PASS' } else { 'FAIL' }
$generatedAt = [DateTimeOffset]::Now

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$jsonPath = Join-Path $OutputDirectory 'e2e-proof.json'
$htmlPath = Join-Path $OutputDirectory 'e2e-proof.html'
$report = [ordered]@{
    schemaVersion = 1
    generatedAt = $generatedAt.ToString('o')
    overallResult = $overallResult
    architecture = [ordered]@{
        proofModel = 'Two linked gates'
        gate1 = 'GitHub Actions to ephemeral Azure runner to private Key Vault to Playwright'
        gate2 = 'Isolated Conditional Access positive and negative enforcement'
        privateLinkService = 'Not used: the runner exposes no inbound service'
        privateEndpoint = 'Used for the Key Vault data path'
    }
    github = [ordered]@{
        repository = $runner.repository
        runId = $run.databaseId
        runUrl = $run.url
        headSha = $run.headSha
        oidcSubject = $github.subject
    }
    conditionalAccess = [ordered]@{
        policyId = $negative.policyId
        positiveCorrelationId = $positive.correlationId
        negativeCorrelationId = $negative.correlationId
        negativeErrorCode = $negative.errorCode
        finalRecordedState = $conditionalAccess.policyState
    }
    summary = [ordered]@{
        passed = $checks.Count - $failedChecks.Count
        failed = $failedChecks.Count
        total = $checks.Count
    }
    checks = @($checks)
}
$report | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $jsonPath -Encoding utf8NoBOM
$jsonHash = (
    Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256
).Hash.ToLowerInvariant()

$rows = foreach ($check in $checks) {
    $class = if ($check.result -eq 'PASS') { 'pass' } else { 'fail' }
    @"
<tr>
  <td>$(ConvertTo-HtmlText $check.stage)</td>
  <td>$(ConvertTo-HtmlText $check.name)</td>
  <td><span class="badge $class">$(ConvertTo-HtmlText $check.result)</span></td>
  <td>$(ConvertTo-HtmlText $check.source)</td>
  <td><code>$(ConvertTo-HtmlText $check.evidence)</code></td>
</tr>
"@
}
$html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Entra CBA Playwright E2E Proof</title>
  <style>
    :root { color-scheme: dark; font-family: "Segoe UI", system-ui, sans-serif; }
    body { margin: 0; background: #08111f; color: #e8eef8; }
    main { max-width: 1500px; margin: 0 auto; padding: 32px; }
    h1 { margin-bottom: 8px; font-size: 2.25rem; }
    h2 { margin-top: 32px; }
    p { color: #b8c5d9; line-height: 1.55; }
    .hero, .card { border: 1px solid #263854; border-radius: 16px; background: #101c2e; }
    .hero { padding: 28px; border-left: 8px solid $(if ($overallResult -eq 'PASS') { '#36d399' } else { '#fb7185' }); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 20px; }
    .card { padding: 18px; }
    .metric { font-size: 2rem; font-weight: 700; }
    .pass { background: #073b2b; color: #7fffc8; border: 1px solid #1f8f68; }
    .fail { background: #4b1420; color: #ff9aac; border: 1px solid #b93851; }
    .badge { display: inline-block; border-radius: 999px; padding: 4px 10px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: #101c2e; border: 1px solid #263854; }
    th, td { padding: 12px; border-bottom: 1px solid #263854; text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; background: #17263d; }
    code { color: #b8e1ff; overflow-wrap: anywhere; }
    a { color: #78c7ff; }
    .warning { border-left: 5px solid #f7b955; }
  </style>
</head>
<body>
<main>
  <section class="hero">
    <span class="badge $(if ($overallResult -eq 'PASS') { 'pass' } else { 'fail' })">$overallResult</span>
    <h1>Entra CBA + Playwright E2E proof</h1>
    <p>Generated $(ConvertTo-HtmlText $generatedAt.ToString('o')). This is a read-only evidence replay backed by live GitHub and Azure API queries, SHA-256 receipt verification, sanitized Entra sign-in evidence, and the atomic restoration journal.</p>
  </section>
  <section class="grid">
    <article class="card"><div class="metric">$($checks.Count - $failedChecks.Count)/$($checks.Count)</div><p>proof checks passed</p></article>
    <article class="card"><div class="metric">$($run.databaseId)</div><p><a href="$(ConvertTo-HtmlText $run.url)">exact GitHub Actions run</a></p></article>
    <article class="card"><div class="metric">$($negative.errorCode)</div><p>isolated SFA rejection error</p></article>
    <article class="card"><div class="metric">$($matchingContainers.Count) / $($matchingRunners.Count)</div><p>matching ACI containers / GitHub runners</p></article>
  </section>
  <section>
    <h2>What was proven</h2>
    <div class="grid">
      <article class="card"><strong>Gate 1: cloud execution</strong><p>GitHub Actions → unique ephemeral ACI runner → delegated subnet and NAT → Key Vault Private Endpoint/private DNS → OIDC credential retrieval → Playwright exact-identity assertion.</p></article>
      <article class="card"><strong>Gate 2: policy enforcement</strong><p>MFA-classified certificate succeeded. SFA-classified certificate failed the exact lab policy with error 500187 while the three interfering managed policies were isolated, then restored.</p></article>
      <article class="card warning"><strong>Private Link boundary</strong><p>Private Endpoint is used for the Key Vault data path. Azure Private Link Service is intentionally not used because this runner exposes no inbound service; it is outbound-only.</p></article>
    </div>
  </section>
  <section>
    <h2>Step-by-step verification</h2>
    <table>
      <thead><tr><th>Stage</th><th>Assertion</th><th>Result</th><th>Source</th><th>Evidence</th></tr></thead>
      <tbody>
        $($rows -join [Environment]::NewLine)
      </tbody>
    </table>
  </section>
  <section>
    <h2>Receipt integrity</h2>
    <p>Machine-readable report: <code>$(ConvertTo-HtmlText $jsonPath)</code></p>
    <p>Report SHA-256: <code>$jsonHash</code></p>
    <p>The original bounded GitHub receipts are independently re-hashed above. No certificate, private key, passphrase, access token, or raw sign-in record is included in this page.</p>
  </section>
</main>
</body>
</html>
"@
$html | Set-Content -LiteralPath $htmlPath -Encoding utf8NoBOM

Write-Host (
    "E2E_SHOWCASE_$overallResult checks=$($checks.Count) " +
    "passed=$($checks.Count - $failedChecks.Count) failed=$($failedChecks.Count)"
)
Write-Host "REPORT_HTML=$htmlPath"
Write-Host "REPORT_JSON=$jsonPath"
Write-Host "REPORT_JSON_SHA256=$jsonHash"

if ($failedChecks.Count -ne 0) {
    throw (
        "E2E showcase failed: " +
        (($failedChecks | ForEach-Object { "$($_.stage): $($_.name)" }) -join ' | ')
    )
}
