[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repository,
    # Public immutable image and archive integrity pins, not deployment credentials.
    [string]$RunnerImage = 'mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e',
    [string]$RunnerVersion = '2.337.0',
    [string]$RunnerSha256 = '70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613',
    [string]$WorkflowFile = 'entra-cba-playwright-poc.yml',
    [string]$Ref,
    [switch]$Dispatch,
    [ValidateRange(10, 30)][int]$RegistrationTimeoutMinutes = 15,
    [ValidateRange(5, 60)][int]$TimeoutMinutes = 30
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$githubStatePath = Join-Path $stateDirectory 'github.json'
$infrastructureStatePath = Join-Path $stateDirectory 'infrastructure.json'
$runnerStatePath = Join-Path $stateDirectory 'runner.json'
$runnerOperationStatePath = Join-Path $stateDirectory 'runner-operation.json'
$runnerOperationLockPath = Join-Path $stateDirectory 'runner-operation.lock'
$ciEvidenceRoot = Join-Path $labRoot '.artifacts\ci'
. (Join-Path $PSScriptRoot 'Runner-Network.ps1')
. (Join-Path $PSScriptRoot 'Proof-Set.ps1')
. (Join-Path $PSScriptRoot 'Workflow-Privacy.ps1')
. (Join-Path $PSScriptRoot 'Federated-Credential.ps1')

foreach ($requiredPath in @(
    $applicationStatePath,
    $entraStatePath,
    $githubStatePath,
    $infrastructureStatePath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}
if ($RunnerVersion -notmatch '^\d+\.\d+\.\d+$' -or $RunnerSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'The runner version or SHA-256 pin is invalid.'
}
if ($RunnerImage -notmatch '^mcr\.microsoft\.com/playwright@sha256:[a-f0-9]{64}$') {
    throw 'The Playwright runner image must use an immutable MCR SHA-256 digest.'
}
if ($WorkflowFile -notmatch '^[A-Za-z0-9_.-]+\.ya?ml$') {
    throw "Workflow file '$WorkflowFile' contains unsupported characters."
}

$application = Get-Content -LiteralPath $applicationStatePath -Raw | ConvertFrom-Json
$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
$github = Get-Content -LiteralPath $githubStatePath -Raw | ConvertFrom-Json
$infrastructure = Get-Content -LiteralPath $infrastructureStatePath -Raw | ConvertFrom-Json
if ($github.repository -cne $Repository) {
    throw "GitHub state belongs to '$($github.repository)', not '$Repository'."
}
if (
    $github.status -cne 'verified' -or
    $github.environmentCreated -ne $true -or
    $github.federatedCredentialCreated -ne $true
) {
    throw 'GitHub OIDC and environment state is not fully verified.'
}
if ($application.tenantId -ne $infrastructure.tenantId -or
    $entra.tenantId -ne $infrastructure.tenantId -or
    $application.testUsername -cne $entra.testUserUpn) {
    throw 'Application, Entra, and infrastructure state do not describe the same lab identity.'
}
if (-not $Ref) {
    $Ref = (& git -C $labRoot branch --show-current).Trim()
}
if (-not $Ref -or @($github.allowedBranches) -cnotcontains $Ref) {
    throw "Ref '$Ref' is not in the exact GitHub environment branch allowlist."
}
az account set --subscription $infrastructure.subscriptionId
$azureAccount = az account show --output json | ConvertFrom-Json
if ($azureAccount.id -ne $infrastructure.subscriptionId -or
    $azureAccount.tenantId -ne $infrastructure.tenantId) {
    throw 'Azure CLI context does not match the stored subscription and tenant.'
}
$liveFederatedCredentials = @(
    az identity federated-credential list `
        --identity-name $infrastructure.outputs.workloadIdentityName.value `
        --resource-group $infrastructure.resourceGroup `
        --output json | ConvertFrom-Json
)
Assert-ExactFederatedCredentialSet `
    -Credentials $liveFederatedCredentials `
    -ExpectedName $github.federatedCredentialName `
    -ExpectedIssuer $github.issuer `
    -ExpectedSubject $github.subject `
    -ExpectedAudience 'api://AzureADTokenExchange' | Out-Null
$runnerNetwork = Get-RunnerNetworkContract -Infrastructure $infrastructure
if (-not $github.network -or
    $github.network.runnerSubnetId -ne $runnerNetwork.runnerSubnetId -or
    $github.network.runnerSubnetCidr -ne $runnerNetwork.runnerSubnetCidr -or
    $github.network.privateEndpointIp -ne $runnerNetwork.privateEndpointIp -or
    $github.network.runnerOutboundIp -ne $runnerNetwork.runnerOutboundIp) {
    throw 'GitHub state does not match the current Azure runner network. Rerun Configure-GitHubOidc.ps1.'
}
$workflowLogProtectedValues = Get-WorkflowLogProtectedValues `
    -Application $application `
    -Entra $entra `
    -GitHub $github `
    -Infrastructure $infrastructure `
    -RunnerNetwork $runnerNetwork

try {
    $runnerOperationLock = [IO.File]::Open(
        $runnerOperationLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another ephemeral-runner operation owns the exclusive local lock.'
}
try {

$repo = gh repo view $Repository --json nameWithOwner,viewerPermission,url | ConvertFrom-Json
if ($repo.nameWithOwner -cne $Repository -or $repo.viewerPermission -ne 'ADMIN') {
    throw "GitHub ADMIN permission for '$Repository' is required."
}

$runnerSubnetId = $infrastructure.outputs.runnerSubnetId.value
if (-not $runnerSubnetId) {
    throw 'Infrastructure state does not contain a runner subnet.'
}

function Write-RunnerStateAtomically {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Collections.IDictionary]$State
    )

    $writeId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$Path.$writeId.tmp"
    $backupPath = "$Path.$writeId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($State | ConvertTo-Json -Depth 10),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace($temporaryPath, $Path, $backupPath, $true)
        }
        else {
            [IO.File]::Move($temporaryPath, $Path)
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

function Remove-AciContainerGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$LauncherId,
        [Parameter(Mandatory)][string]$RepositoryId,
        [Parameter(Mandatory)][string]$ExpiresAtUtc,
        [switch]$RequireAppearanceWindow
    )

    $appearanceDeadline = (Get-Date).AddMinutes(10)
    $cleanupDeadline = $appearanceDeadline.AddMinutes(2)
    $containerObserved = $false
    $consecutiveAbsenceChecks = 0
    do {
        $matchingContainers = @(
            @(
                az container list `
                    --resource-group $infrastructure.resourceGroup `
                    --output json | ConvertFrom-Json
            ) | Where-Object {
                $_.name -ceq $Name
            }
        )
        if ($matchingContainers.Count -gt 1) {
            throw "Azure returned duplicate ACI runner name '$Name'."
        }
        if ($matchingContainers.Count -eq 1) {
            $container = $matchingContainers[0]
            if (
                $container.tags.component -cne 'github-runner' -or
                $container.tags.managedBy -cne 'script' -or
                $container.tags.workload -cne 'entra-cba-playwright' -or
                $container.tags.launcherId -cne $LauncherId -or
                $container.tags.operationId -cne $LauncherId -or
                $container.tags.expiresAtUtc -cne $ExpiresAtUtc -or
                [string]$container.tags.repositoryId -cne $RepositoryId
            ) {
                throw "ACI runner '$Name' is not owned by launcher '$LauncherId'."
            }
            $containerObserved = $true
            $consecutiveAbsenceChecks = 0
            az container delete `
                --name $Name `
                --resource-group $infrastructure.resourceGroup `
                --yes `
                --output none
        }
        elseif (
            $containerObserved -or
            -not $RequireAppearanceWindow -or
            (Get-Date) -ge $appearanceDeadline
        ) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return
            }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $cleanupDeadline)

    throw "ACI container group '$Name' was not verifiably absent after deletion."
}

function Get-RepositoryRunners {
    return @(
    gh api `
        --paginate `
        "repos/$Repository/actions/runners?per_page=100" `
        --jq '.runners[]' | ConvertFrom-Json
    )
}

function Remove-ExactRepositoryRunner {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Label,
        [AllowNull()][string]$RunnerId,
        [switch]$RequireAppearanceWindow
    )

    $appearanceDeadline = (Get-Date).AddSeconds(30)
    $cleanupDeadline = $appearanceDeadline.AddMinutes(2)
    $runnerObserved = [bool]$RunnerId
    $consecutiveAbsenceChecks = 0
    do {
        $matchingRunners = @(Get-RepositoryRunners | Where-Object {
            $_.name -ceq $Name
        })
        if ($matchingRunners.Count -gt 1) {
            throw "More than one GitHub runner is named '$Name'."
        }
        if ($matchingRunners.Count -eq 1) {
            $runner = $matchingRunners[0]
            $runnerLabels = @($runner.labels | ForEach-Object { $_.name })
            if (
                ($RunnerId -and [string]$runner.id -cne $RunnerId) -or
                $runnerLabels.Count -ne 1 -or
                $runnerLabels[0] -cne $Label
            ) {
                throw "GitHub runner '$Name' does not match the exact journaled identity."
            }
            if ($runner.status -ne 'offline' -or $runner.busy) {
                $consecutiveAbsenceChecks = 0
                Start-Sleep -Seconds 5
                continue
            }
            $runnerObserved = $true
            $consecutiveAbsenceChecks = 0
            gh api `
                --method DELETE `
                "repos/$Repository/actions/runners/$($runner.id)" `
                --silent
        }
        elseif (
            $runnerObserved -or
            -not $RequireAppearanceWindow -or
            (Get-Date) -ge $appearanceDeadline
        ) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return
            }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $cleanupDeadline)

    throw "GitHub runner '$Name' was not verifiably deregistered."
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actual = @($Object.PSObject.Properties.Name | Sort-Object -CaseSensitive)
    $expectedNames = @($Expected | Sort-Object -CaseSensitive)
    if ($actual.Count -ne $expectedNames.Count -or
        (Compare-Object $expectedNames $actual -CaseSensitive)) {
        throw "$Label contains unexpected or missing properties."
    }
}

$existingRunners = @(Get-RepositoryRunners | Where-Object {
    $_.name -like 'aci-entra-cba-*'
})
$existingContainers = @(
    @(
        az container list `
            --resource-group $infrastructure.resourceGroup `
            --output json | ConvertFrom-Json
    ) | Where-Object {
        $_.tags.workload -eq 'entra-cba-playwright' -and
        $_.tags.component -eq 'github-runner'
    }
)
$existingRunnerOperation = if (
    Test-Path -LiteralPath $runnerOperationStatePath -PathType Leaf
) {
    Get-Content -LiteralPath $runnerOperationStatePath -Raw |
        ConvertFrom-Json -AsHashtable
}
else {
    $null
}
if (-not $existingRunnerOperation) {
    if ($existingRunners.Count -ne 0 -or $existingContainers.Count -ne 0) {
        throw (
            'An ACI runner or GitHub runner exists without exact local ownership state. ' +
            'No cloud resource was deleted.'
        )
    }
}
else {
    $expectedRunnerNameSuffix = if (
        ([string]$existingRunnerOperation.launcherId).Length -gt 16
    ) {
        ([string]$existingRunnerOperation.launcherId).Substring(0, 8)
    }
    else {
        [string]$existingRunnerOperation.launcherId
    }
    $expectedRunnerName = "aci-entra-cba-$expectedRunnerNameSuffix"
    $recordedExpiry = [DateTimeOffset]::MinValue
    if (
        [int]$existingRunnerOperation.schemaVersion -ne 1 -or
        $existingRunnerOperation.status -notin @('planned', 'created', 'registered') -or
        $existingRunnerOperation.repository -cne $Repository -or
        [string]$existingRunnerOperation.repositoryId -cne
            [string]$github.repositoryId -or
        $existingRunnerOperation.subscriptionId -ine $infrastructure.subscriptionId -or
        $existingRunnerOperation.resourceGroup -cne $infrastructure.resourceGroup -or
        $existingRunnerOperation.containerName -cne $expectedRunnerName -or
        $existingRunnerOperation.runnerName -cne $expectedRunnerName -or
        -not $existingRunnerOperation.runnerLabel -or
        -not $existingRunnerOperation.launcherId -or
        -not [DateTimeOffset]::TryParse(
            [string]$existingRunnerOperation.expiresAtUtc,
            [ref]$recordedExpiry
        ) -or
        (
            $existingRunnerOperation.status -ceq 'registered' -and
            -not $existingRunnerOperation.runnerId
        )
    ) {
        throw 'Ephemeral-runner operation state does not match the exact lab contract.'
    }
    $unexpectedContainers = @($existingContainers | Where-Object {
        $_.name -cne $existingRunnerOperation.containerName
    })
    $unexpectedRunners = @($existingRunners | Where-Object {
        $_.name -cne $existingRunnerOperation.runnerName
    })
    if ($unexpectedContainers.Count -ne 0 -or $unexpectedRunners.Count -ne 0) {
        throw 'Unjournaled ACI or GitHub runner resources exist and were not deleted.'
    }
    $recordedContainer = @($existingContainers | Where-Object {
        $_.name -ceq $existingRunnerOperation.containerName
    })
    if ($recordedContainer.Count -eq 1) {
        $details = az container show `
            --name $existingRunnerOperation.containerName `
            --resource-group $infrastructure.resourceGroup `
            --output json | ConvertFrom-Json
        $currentState = $null
        if (
            @($details.containers).Count -eq 1 -and
            $null -ne $details.containers[0].instanceView -and
            $null -ne $details.containers[0].instanceView.currentState
        ) {
            $currentState = [string]$details.containers[0].instanceView.currentState.state
        }
        $expiresAt = [DateTimeOffset]::MinValue
        $hasValidExpiry = [DateTimeOffset]::TryParse(
            [string]$details.tags.expiresAtUtc,
            [ref]$expiresAt
        )
        if (
            $currentState -notin @('Terminated', 'Failed') -and
            (
                -not $hasValidExpiry -or
                $expiresAt -gt [DateTimeOffset]::UtcNow
            )
        ) {
            throw "Journaled ACI runner '$($details.name)' is still active."
        }
    }
    Remove-AciContainerGroup `
        -Name $existingRunnerOperation.containerName `
        -LauncherId ([string]$existingRunnerOperation.launcherId) `
        -RepositoryId ([string]$existingRunnerOperation.repositoryId) `
        -ExpiresAtUtc ([string]$existingRunnerOperation.expiresAtUtc) `
        -RequireAppearanceWindow:(
            $existingRunnerOperation.status -ceq 'planned'
        )
    Remove-ExactRepositoryRunner `
        -Name $existingRunnerOperation.runnerName `
        -Label $existingRunnerOperation.runnerLabel `
        -RunnerId ([string]$existingRunnerOperation.runnerId) `
        -RequireAppearanceWindow:(-not $existingRunnerOperation.runnerId)
    Remove-Item -LiteralPath $runnerOperationStatePath -Force
}

$localHeadSha = (& git -C $labRoot rev-parse HEAD).Trim()
$encodedRef = [Uri]::EscapeDataString($Ref)
$remoteHeadSha = gh api `
    "repos/$Repository/commits/$encodedRef" `
    --jq .sha
if (-not $localHeadSha -or $remoteHeadSha -ne $localHeadSha) {
    throw "Local HEAD '$localHeadSha' is not the exact pushed head of '$Ref'."
}

$workflowRun = $null
if ($Dispatch) {
    $verificationId = [guid]::NewGuid().ToString()
    $runnerLabel = "entra-cba-poc-$verificationId"
    $expectedWorkflowEvent = 'workflow_dispatch'
} else {
    $pushRuns = @(
        gh api `
            --paginate `
            "repos/$Repository/actions/runs?event=push&branch=$encodedRef&per_page=100" `
            --jq '.workflow_runs[]' | ConvertFrom-Json
    )
    $matchingPushRuns = @($pushRuns | Where-Object {
        $_.head_sha -eq $localHeadSha -and
        $_.path -ceq ".github/workflows/$WorkflowFile" -and
        $_.status -eq 'queued'
    })
    if ($matchingPushRuns.Count -ne 1) {
        throw (
            "Expected one queued push workflow for '$Ref' at '$localHeadSha', " +
            "but found $($matchingPushRuns.Count). Use -Dispatch only after the workflow exists on the default branch."
        )
    }
    $workflowRun = $matchingPushRuns[0]
    $verificationId = [string]$workflowRun.id
    $runnerLabel = "entra-cba-poc-run-$verificationId"
    $expectedWorkflowEvent = 'push'
}
$expectedRunTitle = 'Entra CBA privacy-verified proof'
$runnerNameSuffix = if ($verificationId.Length -gt 16) {
    $verificationId.Substring(0, 8)
} else {
    $verificationId
}
$runnerName = "aci-entra-cba-$runnerNameSuffix"
$containerName = $runnerName
$runnerExpiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(
    $RegistrationTimeoutMinutes + $TimeoutMinutes + 10
).ToString('o')
$runnerAssetUrl = (
    "https://github.com/actions/runner/releases/download/v$RunnerVersion/" +
    "actions-runner-linux-x64-$RunnerVersion.tar.gz"
)
$runnerScript = @'
set -euo pipefail
export RUNNER_ALLOW_RUNASROOT=1
install_dir=/opt/actions-runner
archive=/tmp/actions-runner.tar.gz
mkdir -p "$install_dir"
cd "$install_dir"
curl --fail --location --proto '=https' --retry 5 --retry-all-errors --show-error --silent "$RUNNER_ASSET_URL" --output "$archive"
printf "%s  %s\n" "$RUNNER_SHA256" "$archive" | sha256sum --check --strict
tar --extract --file "$archive" --gzip
rm -f "$archive"
./config.sh \
  --disableupdate \
  --ephemeral \
  --labels "$RUNNER_LABEL" \
  --name "$RUNNER_NAME" \
  --no-default-labels \
  --replace \
  --token "$RUNNER_TOKEN" \
  --unattended \
  --url "$REPOSITORY_URL" \
  --work _work
unset RUNNER_TOKEN
set +e
timeout --signal=TERM --kill-after=30 "${RUNNER_TIMEOUT_SECONDS}s" ./run.sh
runner_exit_code=$?
set -e
if [ "$runner_exit_code" -eq 124 ] || [ "$runner_exit_code" -eq 137 ]; then
  printf "Runner lifetime limit reached.\n" >&2
  exit 1
fi
exit "$runner_exit_code"
'@
$runnerScript = $runnerScript.Replace("`r`n", "`n")

$registrationToken = (
    gh api `
        --method POST `
        "repos/$Repository/actions/runners/registration-token" `
        --jq .token
)
if (-not $registrationToken) {
    throw 'GitHub did not return a runner registration token.'
}

$containerBody = @{
    location = $infrastructure.location
    properties = @{
        containers = @(
            @{
                name = 'runner'
                properties = @{
                    command = @('/bin/bash', '-c', $runnerScript)
                    environmentVariables = @(
                        @{ name = 'REPOSITORY_URL'; value = $repo.url }
                        @{ name = 'RUNNER_ASSET_URL'; value = $runnerAssetUrl }
                        @{ name = 'RUNNER_LABEL'; value = $runnerLabel }
                        @{ name = 'RUNNER_NAME'; value = $runnerName }
                        @{ name = 'RUNNER_SHA256'; value = $RunnerSha256.ToLowerInvariant() }
                        @{ name = 'RUNNER_TOKEN'; secureValue = $registrationToken }
                        @{ name = 'RUNNER_TIMEOUT_SECONDS'; value = [string]($TimeoutMinutes * 60) }
                    )
                    image = $RunnerImage
                    resources = @{
                        requests = @{
                            cpu = 2
                            memoryInGB = 4
                        }
                    }
                }
            }
        )
        osType = 'Linux'
        restartPolicy = 'Never'
        subnetIds = @(
            @{ id = $runnerSubnetId }
        )
    }
    tags = @{
        component = 'github-runner'
        environment = 'poc'
        expiresAtUtc = $runnerExpiresAtUtc
        launcherId = $verificationId
        managedBy = 'script'
        operationId = $verificationId
        repositoryId = [string]$github.repositoryId
        workload = 'entra-cba-playwright'
    }
}

$managementToken = az account get-access-token `
    --resource 'https://management.azure.com/' `
    --query accessToken `
    --output tsv
if (-not $managementToken) {
    throw 'Unable to obtain an Azure Resource Manager access token.'
}
$managementHeaders = @{ Authorization = "Bearer $managementToken" }
$containerUri = (
    "https://management.azure.com/subscriptions/$($infrastructure.subscriptionId)" +
    "/resourceGroups/$($infrastructure.resourceGroup)/providers/Microsoft.ContainerInstance" +
    "/containerGroups/$containerName`?api-version=2023-05-01"
)

$evidenceArtifactId = $null
$expectedArtifactName = $null
$workflowLogPrivacy = $null
$state = $null
$runnerOperation = [ordered]@{
    containerName = $containerName
    expiresAtUtc = $runnerExpiresAtUtc
    launcherId = $verificationId
    ref = $Ref
    repository = $Repository
    repositoryId = [string]$github.repositoryId
    resourceGroup = $infrastructure.resourceGroup
    runnerId = $null
    runnerImage = $RunnerImage
    runnerLabel = $runnerLabel
    runnerName = $runnerName
    schemaVersion = 1
    status = 'planned'
    subscriptionId = $infrastructure.subscriptionId
    workflowFile = $WorkflowFile
}
Write-RunnerStateAtomically `
    -Path $runnerOperationStatePath `
    -State $runnerOperation
try {
    Invoke-RestMethod `
        -Method Put `
        -Uri $containerUri `
        -Headers $managementHeaders `
        -ContentType 'application/json' `
        -Body ($containerBody | ConvertTo-Json -Depth 20) | Out-Null
    $runnerOperation.status = 'created'
    Write-RunnerStateAtomically `
        -Path $runnerOperationStatePath `
        -State $runnerOperation
    $registrationToken = $null
    $containerBody = $null

    $state = [ordered]@{
        containerName = $containerName
        label = $runnerLabel
        network = $runnerNetwork
        repository = $Repository
        ref = $Ref
        runnerImage = $RunnerImage
        runnerName = $runnerName
        runnerVersion = $RunnerVersion
        startedAt = (Get-Date).ToString('o')
        verificationId = $verificationId
        workflowFile = $WorkflowFile
    }
    Write-RunnerStateAtomically -Path $runnerStatePath -State $state

    $registrationDeadline = (Get-Date).AddMinutes($RegistrationTimeoutMinutes)
    $registeredRunner = $null
    do {
        Start-Sleep -Seconds 10
        $runners = @(Get-RepositoryRunners)
        $registeredRunner = @($runners | Where-Object { $_.name -eq $runnerName })
        if ($registeredRunner.Count -gt 1) {
            throw "More than one runner is named '$runnerName'."
        }
    } while ($registeredRunner.Count -eq 0 -and (Get-Date) -lt $registrationDeadline)

    if ($registeredRunner.Count -ne 1) {
        $container = az container show `
            --name $containerName `
            --resource-group $infrastructure.resourceGroup `
            --output json | ConvertFrom-Json
        try {
            $logs = (az container logs `
                --name $containerName `
                --resource-group $infrastructure.resourceGroup) -join [Environment]::NewLine
        } catch {
            $logs = "Unavailable: $($_.Exception.Message)"
        }
        throw (
            "Runner did not register within $RegistrationTimeoutMinutes minutes. " +
            'Container provisioning state: ' +
            "'$($container.provisioningState)'. Logs: $logs"
        )
    }
    $runnerOperation.runnerId = [string]$registeredRunner[0].id
    $runnerOperation.status = 'registered'
    Write-RunnerStateAtomically `
        -Path $runnerOperationStatePath `
        -State $runnerOperation

    $runnerContainerGroup = az container show `
        --name $containerName `
        --resource-group $infrastructure.resourceGroup `
        --output json | ConvertFrom-Json
    if (@($runnerContainerGroup.subnetIds).Count -ne 1 -or
        $runnerContainerGroup.subnetIds[0].id -ne $runnerNetwork.runnerSubnetId -or
        @($runnerContainerGroup.containers).Count -ne 1 -or
        $runnerContainerGroup.containers[0].image -cne $RunnerImage -or
        $runnerContainerGroup.restartPolicy -ne 'Never' -or
        $runnerContainerGroup.tags.launcherId -ne $verificationId -or
        $runnerContainerGroup.tags.component -ne 'github-runner') {
        throw 'The provisioned ACI runner does not match the exact image, subnet, lifecycle, and launch ID.'
    }
    $runnerPrivateIpv4 = [string]$runnerContainerGroup.ipAddress.ip
    if ($runnerPrivateIpv4 -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$' -or
        -not (Test-Ipv4AddressInCidr `
            -Address $runnerPrivateIpv4 `
            -Cidr $runnerNetwork.runnerSubnetCidr)) {
        throw 'The live ACI runner does not have one expected private address in the delegated subnet.'
    }
    $runnerPrivateIpv4InExpectedSubnetSha256 = Get-TextSha256 -Text (
        ConvertTo-Json -InputObject @($runnerPrivateIpv4) -Compress
    )
    $workflowLogProtectedValues['ACI runner private IP'] = $runnerPrivateIpv4
    $state.runnerPrivateIpv4 = $runnerPrivateIpv4
    $state.runnerPrivateIpv4InExpectedSubnetSha256 = (
        $runnerPrivateIpv4InExpectedSubnetSha256
    )

    Write-Host "RUNNER_READY name=$runnerName label=$runnerLabel"

    if ($Dispatch) {
        $dispatchStartedAt = [DateTimeOffset]::UtcNow
        gh workflow run $WorkflowFile `
            --repo $Repository `
            --ref $Ref `
            --field "verification_id=$verificationId" `
            --field "runner_label=$runnerLabel"

        $encodedWorkflow = [Uri]::EscapeDataString($WorkflowFile)
        $runsUri = (
            "repos/$Repository/actions/workflows/$encodedWorkflow/runs" +
            "?event=workflow_dispatch&branch=$encodedRef&per_page=20"
        )
        $runDiscoveryDeadline = (Get-Date).AddMinutes(3)
        do {
            Start-Sleep -Seconds 5
            $workflowRuns = @((gh api $runsUri | ConvertFrom-Json).workflow_runs)
            $matchingRuns = @($workflowRuns | Where-Object {
                $_.display_title -ceq $expectedRunTitle -and
                $_.event -eq 'workflow_dispatch' -and
                $_.head_branch -ceq $Ref -and
                $_.head_sha -eq $localHeadSha -and
                $_.path -ceq ".github/workflows/$WorkflowFile" -and
                [DateTimeOffset]::Parse($_.created_at) -ge $dispatchStartedAt.AddMinutes(-1)
            })
            if ($matchingRuns.Count -gt 1) {
                throw "More than one workflow run matched verification '$verificationId'."
            }
            if ($matchingRuns.Count -eq 1) {
                $workflowRun = $matchingRuns[0]
            }
        } while (-not $workflowRun -and (Get-Date) -lt $runDiscoveryDeadline)
        if (-not $workflowRun) {
            throw "GitHub did not create the workflow run for verification '$verificationId'."
        }
    } else {
        Write-Host "USING_QUEUED_PUSH_RUN runId=$($workflowRun.id) sha=$($workflowRun.head_sha)"
    }

    $completionDeadline = (Get-Date).AddMinutes($TimeoutMinutes)
    do {
        Start-Sleep -Seconds 10
        $workflowRun = gh api "repos/$Repository/actions/runs/$($workflowRun.id)" | ConvertFrom-Json
        $container = az container show `
            --name $containerName `
            --resource-group $infrastructure.resourceGroup `
            --output json | ConvertFrom-Json
        $currentState = $null
        if (
            @($container.containers).Count -eq 1 -and
            $null -ne $container.containers[0].instanceView
        ) {
            $currentState = $container.containers[0].instanceView.currentState
        }
        $currentStateName = if ($null -ne $currentState) {
            [string]$currentState.state
        } else {
            ''
        }
    } while (
        (
            $workflowRun.status -ne 'completed' -or
            $currentStateName -notin @('Terminated', 'Failed')
        ) -and
        (Get-Date) -lt $completionDeadline
    )

    if (
        $workflowRun.status -ne 'completed' -or
        $currentStateName -notin @('Terminated', 'Failed')
    ) {
        throw "Workflow or runner exceeded the $TimeoutMinutes-minute lifetime limit."
    }
    $exitCode = if ($null -ne $currentState) {
        $currentState.exitCode
    } else {
        $null
    }
    if ($null -eq $exitCode -or $exitCode -ne 0) {
        throw "Runner container exited with code '$exitCode'."
    }
    if ($workflowRun.display_title -cne $expectedRunTitle -or
        $workflowRun.event -ne $expectedWorkflowEvent -or
        $workflowRun.head_branch -cne $Ref) {
        throw 'The completed workflow run does not match the exact dispatch request.'
    }

    $jobsResponse = gh api "repos/$Repository/actions/runs/$($workflowRun.id)/jobs" | ConvertFrom-Json
    $jobs = @($jobsResponse.jobs)
    if ($jobs.Count -ne 1 -or
        $jobs[0].name -cne 'Verify Entra CBA' -or
        $jobs[0].runner_name -cne $runnerName -or
        @($jobs[0].labels) -cnotcontains $runnerLabel) {
        throw 'The workflow run was not executed by the exact ephemeral runner job.'
    }
    if ($workflowRun.conclusion -ne 'success' -or $jobs[0].conclusion -ne 'success') {
        throw "Workflow run '$($workflowRun.id)' concluded '$($workflowRun.conclusion)'."
    }
    $workflowLogPrivacy = Test-WorkflowLogPrivacy `
        -Repository $Repository `
        -RunId ([long]$workflowRun.id) `
        -ProtectedValues $workflowLogProtectedValues

    $ciEvidenceDirectory = Join-Path $ciEvidenceRoot ([string]$workflowRun.id)
    if (Test-Path -LiteralPath $ciEvidenceDirectory) {
        Remove-Item -LiteralPath $ciEvidenceDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $ciEvidenceDirectory -Force | Out-Null

    $artifactDeadline = (Get-Date).AddSeconds(30)
    $expectedArtifactName = "entra-cba-playwright-$($workflowRun.id)"
    do {
        $artifacts = @(
            @(
                (
                    gh api "repos/$Repository/actions/runs/$($workflowRun.id)/artifacts" |
                        ConvertFrom-Json
                ).artifacts
            ) | Where-Object { $_.name -ceq $expectedArtifactName }
        )
        if ($artifacts.Count -eq 0) {
            Start-Sleep -Seconds 5
        }
    } while ($artifacts.Count -eq 0 -and (Get-Date) -lt $artifactDeadline)
    if ($artifacts.Count -gt 1) {
        throw 'The workflow produced more than one evidence artifact with the expected name.'
    }

    if ($artifacts.Count -ne 1) {
        throw (
            "The workflow did not produce the one required evidence artifact " +
            "'$expectedArtifactName'. Public job-log receipt fallback is disabled."
        )
    }
    if ($artifacts[0].expired -or [int64]$artifacts[0].size_in_bytes -gt 1MB) {
        throw 'The workflow evidence artifact is expired or exceeds the 1 MiB bound.'
    }
    gh run download $workflowRun.id `
        --repo $Repository `
        --name $expectedArtifactName `
        --dir $ciEvidenceDirectory
    $evidenceArtifactId = $artifacts[0].id
    $evidenceTransport = 'artifact'

    $evidenceFiles = @(Get-ChildItem -LiteralPath $ciEvidenceDirectory -Recurse -File)
    $expectedEvidenceNames = @('cba-feasibility.json', 'runner-network.json')
    if ($evidenceFiles.Count -ne 2 -or
        (Compare-Object `
            ($expectedEvidenceNames | Sort-Object -CaseSensitive) `
            ($evidenceFiles.Name | Sort-Object -CaseSensitive) `
            -CaseSensitive)) {
        throw 'The CI artifact does not contain exactly the two expected sanitized receipts.'
    }
    if (@($evidenceFiles | Where-Object { $_.Length -gt 64KB }).Count -ne 0) {
        throw 'A CI evidence receipt exceeds the 64 KiB bound.'
    }

    $identityReceiptPath = Join-Path $ciEvidenceDirectory 'cba-feasibility.json'
    $networkReceiptPath = Join-Path $ciEvidenceDirectory 'runner-network.json'
    $identityReceipt = Get-Content -LiteralPath $identityReceiptPath -Raw | ConvertFrom-Json
    $networkReceipt = Get-Content -LiteralPath $networkReceiptPath -Raw | ConvertFrom-Json
    Assert-ExactProperties `
        -Object $identityReceipt `
        -Expected @(
            'githubRunId',
            'githubSha',
            'identitySha256',
            'schemaVersion',
            'verificationIdSha256',
            'verifiedAt'
        ) `
        -Label 'Identity receipt'
    Assert-ExactProperties `
        -Object $networkReceipt `
        -Expected @(
            'azure',
            'github',
            'receiptSha256',
            'runner',
            'schemaVersion',
            'verificationIdSha256',
            'verifiedAt'
        ) `
        -Label 'Runner network receipt'
    Assert-ExactProperties `
        -Object $networkReceipt.azure `
        -Expected @(
            'keyVaultHostSha256',
            'keyVaultRead',
            'privateEndpointIpSha256',
            'resolvedVaultIpv4AddressCount',
            'resolvedVaultIpv4AddressSha256',
            'runnerSubnetCidrSha256'
        ) `
        -Label 'Runner network Azure evidence'
    Assert-ExactProperties `
        -Object $networkReceipt.github `
        -Expected @(
            'oidcAudience',
            'oidcIssuer',
            'oidcSubjectSha256',
            'repository',
            'runId',
            'sha'
        ) `
        -Label 'Runner network GitHub evidence'
    Assert-ExactProperties `
        -Object $networkReceipt.runner `
        -Expected @(
            'architecture',
            'environment',
            'labelSha256',
            'nameSha256',
            'os',
            'privateIpv4AddressCount',
            'privateIpv4InExpectedSubnetCount',
            'privateIpv4InExpectedSubnetSha256'
        ) `
        -Label 'Runner network runtime evidence'

    $expectedIdentityJson = [ordered]@{
        appUrl = $application.appUrl
        objectId = $entra.testUserId
        tenantId = $infrastructure.tenantId
        username = $entra.testUserUpn
    } | ConvertTo-Json -Compress
    $expectedIdentitySha256 = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($expectedIdentityJson)
        )
    ).ToLowerInvariant()
    $verificationIdSha256 = Get-TextSha256 -Text $verificationId
    if ([int]$identityReceipt.schemaVersion -ne 3 -or
        $identityReceipt.verificationIdSha256 -cne $verificationIdSha256 -or
        [string]$identityReceipt.githubRunId -ne [string]$workflowRun.id -or
        $identityReceipt.githubSha -ne $workflowRun.head_sha -or
        $identityReceipt.identitySha256 -cne $expectedIdentitySha256) {
        throw 'The identity receipt does not match the exact workflow revision and lab identity.'
    }
    if ([int]$networkReceipt.schemaVersion -ne 2 -or
        $networkReceipt.verificationIdSha256 -cne $verificationIdSha256 -or
        $networkReceipt.receiptSha256 -notmatch '^[0-9a-f]{64}$' -or
        $networkReceipt.azure.keyVaultHostSha256 -cne (
            Get-TextSha256 -Text "$($runnerNetwork.keyVaultName).vault.azure.net"
        ) -or
        $networkReceipt.azure.keyVaultRead -ne 'succeeded' -or
        $networkReceipt.azure.privateEndpointIpSha256 -cne (
            Get-TextSha256 -Text $runnerNetwork.privateEndpointIp
        ) -or
        $networkReceipt.azure.runnerSubnetCidrSha256 -cne (
            Get-TextSha256 -Text $runnerNetwork.runnerSubnetCidr
        ) -or
        [int]$networkReceipt.azure.resolvedVaultIpv4AddressCount -ne 1 -or
        $networkReceipt.azure.resolvedVaultIpv4AddressSha256 -cne (
            Get-TextSha256 -Text $runnerNetwork.privateEndpointIp
        ) -or
        $networkReceipt.github.oidcAudience -ne 'api://AzureADTokenExchange' -or
        $networkReceipt.github.oidcIssuer -ne 'https://token.actions.githubusercontent.com' -or
        $networkReceipt.github.oidcSubjectSha256 -cne (
            Get-TextSha256 -Text $github.subject
        ) -or
        $networkReceipt.github.repository -cne $Repository -or
        [string]$networkReceipt.github.runId -ne [string]$workflowRun.id -or
        $networkReceipt.github.sha -ne $workflowRun.head_sha -or
        $networkReceipt.runner.environment -ne 'self-hosted' -or
        $networkReceipt.runner.labelSha256 -cne (
            Get-TextSha256 -Text $runnerLabel
        ) -or
        $networkReceipt.runner.nameSha256 -cne (
            Get-TextSha256 -Text $runnerName
        ) -or
        $networkReceipt.runner.os -ne 'Linux' -or
        $networkReceipt.runner.architecture -ne 'X64' -or
        [int]$networkReceipt.runner.privateIpv4AddressCount -lt 1 -or
        [int]$networkReceipt.runner.privateIpv4InExpectedSubnetCount -ne 1 -or
        $networkReceipt.runner.privateIpv4InExpectedSubnetSha256 -cne
            $runnerPrivateIpv4InExpectedSubnetSha256) {
        throw 'The runner network receipt does not match the exact ACI, OIDC, and Private Endpoint path.'
    }

    $proofSetId = Get-E2eProofSetId `
        -Repository $Repository `
        -RunId ([long]$workflowRun.id) `
        -HeadSha $workflowRun.head_sha `
        -WorkflowFile $WorkflowFile `
        -OidcSubject $github.subject
    $state.completedAt = (Get-Date).ToString('o')
    $state.evidenceArtifactId = $evidenceArtifactId
    $state.evidenceDirectory = $ciEvidenceDirectory
    $state.evidenceTransport = $evidenceTransport
    $state.identityReceiptSha256 = (
        Get-FileHash -LiteralPath $identityReceiptPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $state.networkReceiptSha256 = (
        Get-FileHash -LiteralPath $networkReceiptPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $state.proofSetId = $proofSetId
    $state.workflowLogPrivacyVerified = $true
    $state.workflowLogPrivacyVerifiedAt = $workflowLogPrivacy.verifiedAt
    $state.workflowLogProtectedValueCount = $workflowLogPrivacy.protectedValueCount
    $state.workflowLogSha256 = $workflowLogPrivacy.logSha256
    $state.workflowLogVariantCount = $workflowLogPrivacy.variantCount
    $state.workflowConclusion = $workflowRun.conclusion
    $state.workflowEvent = $workflowRun.event
    $state.workflowHeadSha = $workflowRun.head_sha
    $state.workflowRunId = $workflowRun.id
    $state.workflowRunUrl = $workflowRun.html_url
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $runnerStatePath -Encoding utf8NoBOM
} finally {
    $registrationToken = $null
    $containerBody = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        $cleanupWorkflowRun = $workflowRun
        if (-not $cleanupWorkflowRun -and $Dispatch -and $dispatchStartedAt) {
            $candidateRuns = @(
                gh api `
                    --paginate `
                    "repos/$Repository/actions/runs?event=workflow_dispatch&branch=$encodedRef&per_page=100" `
                    --jq '.workflow_runs[]' | ConvertFrom-Json
            )
            $candidateMatches = @($candidateRuns | Where-Object {
                $_.display_title -ceq $expectedRunTitle -and
                $_.event -eq 'workflow_dispatch' -and
                $_.head_branch -ceq $Ref -and
                $_.head_sha -eq $localHeadSha -and
                $_.path -ceq ".github/workflows/$WorkflowFile" -and
                [DateTimeOffset]::Parse($_.created_at) -ge $dispatchStartedAt.AddMinutes(-1)
            })
            if ($candidateMatches.Count -eq 1) {
                $cleanupWorkflowRun = $candidateMatches[0]
            }
        }
        if ($cleanupWorkflowRun -and $cleanupWorkflowRun.id) {
            $cleanupWorkflowRun = gh api `
                "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)" | ConvertFrom-Json
            if ($cleanupWorkflowRun.status -ne 'completed') {
                try {
                    gh api `
                        --method POST `
                        "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)/cancel" `
                        --silent
                } catch {
                    $cleanupWorkflowRun = gh api `
                        "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)" | ConvertFrom-Json
                    if ($cleanupWorkflowRun.status -ne 'completed') {
                        throw
                    }
                }
                $cancellationDeadline = (Get-Date).AddMinutes(2)
                do {
                    Start-Sleep -Seconds 5
                    $cleanupWorkflowRun = gh api `
                        "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)" | ConvertFrom-Json
                } while (
                    $cleanupWorkflowRun.status -ne 'completed' -and
                    (Get-Date) -lt $cancellationDeadline
                )
                if ($cleanupWorkflowRun.status -ne 'completed') {
                    throw "Workflow run '$($cleanupWorkflowRun.id)' did not finish after cancellation."
                }
            }
        }
    } catch {
        $cleanupErrors.Add("Workflow cancellation failed: $($_.Exception.Message)")
    }
    try {
        if ($cleanupWorkflowRun -and $cleanupWorkflowRun.id) {
            $artifactResponse = gh api `
                "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)/artifacts" |
                ConvertFrom-Json
            $solutionArtifacts = @($artifactResponse.artifacts | Where-Object {
                $_.name -like 'entra-cba-playwright-*'
            })
            foreach ($artifact in $solutionArtifacts) {
                gh api `
                    --method DELETE `
                    "repos/$Repository/actions/artifacts/$($artifact.id)" `
                    --silent
            }

            $artifactDeletionDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
            do {
                $remainingArtifactResponse = gh api `
                    "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)/artifacts" |
                    ConvertFrom-Json
                $remainingSolutionArtifacts = @(
                    $remainingArtifactResponse.artifacts | Where-Object {
                        $_.name -like 'entra-cba-playwright-*'
                    }
                )
                if ($remainingSolutionArtifacts.Count -eq 0) {
                    break
                }
                Start-Sleep -Seconds 3
            } while ([DateTimeOffset]::UtcNow -lt $artifactDeletionDeadline)
            if ($remainingSolutionArtifacts.Count -ne 0) {
                throw 'The transient GitHub evidence artifact still exists after deletion.'
            }
        }
    } catch {
        $cleanupErrors.Add("Evidence artifact deletion failed: $($_.Exception.Message)")
    }
    try {
        if ($cleanupWorkflowRun -and
            $cleanupWorkflowRun.id -and
            -not $workflowLogPrivacy) {
            gh api `
                --method DELETE `
                "repos/$Repository/actions/runs/$($cleanupWorkflowRun.id)" `
                --silent
            $recentRunIds = @(
                gh api `
                    --paginate `
                    "repos/$Repository/actions/runs?per_page=100" `
                    --jq '.workflow_runs[].id'
            )
            if ($recentRunIds -contains [string]$cleanupWorkflowRun.id) {
                throw 'The workflow run with an unverified public log still exists after deletion.'
            }
        }
    } catch {
        $cleanupErrors.Add("Unverified workflow run deletion failed: $($_.Exception.Message)")
    }
    try {
        Remove-AciContainerGroup `
            -Name $containerName `
            -LauncherId $verificationId `
            -RepositoryId ([string]$github.repositoryId) `
            -ExpiresAtUtc $runnerExpiresAtUtc `
            -RequireAppearanceWindow:(
                $runnerOperation.status -ceq 'planned'
            )
    } catch {
        $cleanupErrors.Add("ACI deletion failed: $($_.Exception.Message)")
    }
    try {
        Remove-ExactRepositoryRunner `
            -Name $runnerName `
            -Label $runnerLabel `
            -RunnerId ([string]$runnerOperation.runnerId) `
            -RequireAppearanceWindow:(
                -not $runnerOperation.runnerId
            )
    } catch {
        $cleanupErrors.Add("GitHub runner deregistration failed: $($_.Exception.Message)")
    }
    $managementHeaders = $null
    $managementToken = $null
    if ($cleanupErrors.Count -ne 0) {
        throw "Ephemeral runner cleanup failed: $($cleanupErrors -join ' | ')"
    }
    if ($state) {
        $state.aciContainerDeleted = $true
        $state.cleanupVerifiedAt = (Get-Date).ToString('o')
        $state.evidenceArtifactDeleted = $true
        $state.githubRunnerDeregistered = $true
        $state.workflowFinalConclusion = if ($cleanupWorkflowRun) {
            $cleanupWorkflowRun.conclusion
        }
        else {
            $null
        }
        $state.workflowFinalStatus = if ($cleanupWorkflowRun) {
            $cleanupWorkflowRun.status
        }
        else {
            $null
        }
        Write-RunnerStateAtomically -Path $runnerStatePath -State $state
    }
    Remove-Item -LiteralPath $runnerOperationStatePath -Force
}

Write-Host (
    'END_TO_END_VERIFIED conclusion=success privacy=verified cleanup=verified'
)
}
finally {
    $runnerOperationLock.Dispose()
}
