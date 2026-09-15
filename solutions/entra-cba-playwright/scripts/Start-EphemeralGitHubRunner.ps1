[CmdletBinding()]
param(
    [string]$Repository = 'samitks77/dev-agents-solutions',
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
$ciEvidenceRoot = Join-Path $labRoot '.artifacts\ci'
. (Join-Path $PSScriptRoot 'Runner-Network.ps1')
. (Join-Path $PSScriptRoot 'Proof-Set.ps1')

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
$runnerNetwork = Get-RunnerNetworkContract -Infrastructure $infrastructure
if (-not $github.network -or
    $github.network.runnerSubnetId -ne $runnerNetwork.runnerSubnetId -or
    $github.network.runnerSubnetCidr -ne $runnerNetwork.runnerSubnetCidr -or
    $github.network.privateEndpointIp -ne $runnerNetwork.privateEndpointIp -or
    $github.network.runnerOutboundIp -ne $runnerNetwork.runnerOutboundIp) {
    throw 'GitHub state does not match the current Azure runner network. Rerun Configure-GitHubOidc.ps1.'
}

$repo = gh repo view $Repository --json nameWithOwner,viewerPermission,url | ConvertFrom-Json
if ($repo.nameWithOwner -cne $Repository -or $repo.viewerPermission -ne 'ADMIN') {
    throw "GitHub ADMIN permission for '$Repository' is required."
}

$runnerSubnetId = $infrastructure.outputs.runnerSubnetId.value
if (-not $runnerSubnetId) {
    throw 'Infrastructure state does not contain a runner subnet.'
}

function Test-AciContainerGroupExists {
    param([Parameter(Mandatory)][string]$Name)

    $matchingName = az container list `
        --resource-group $infrastructure.resourceGroup `
        --query "[?name=='$Name'].name | [0]" `
        --output tsv
    return [bool]$matchingName
}

function Remove-AciContainerGroup {
    param([Parameter(Mandatory)][string]$Name)

    $deletionDeadline = (Get-Date).AddMinutes(5)
    $consecutiveAbsenceChecks = 0
    do {
        if (Test-AciContainerGroupExists -Name $Name) {
            $consecutiveAbsenceChecks = 0
            az container delete `
                --name $Name `
                --resource-group $infrastructure.resourceGroup `
                --yes `
                --output none
        } else {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return
            }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deletionDeadline)

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

function Test-Ipv4AddressInCidr {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Cidr
    )

    $cidrParts = $Cidr.Split('/')
    if ($cidrParts.Count -ne 2) {
        throw "CIDR '$Cidr' is invalid."
    }
    $prefixLength = [int]$cidrParts[1]
    if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
        throw "CIDR '$Cidr' has an invalid prefix."
    }
    $addressBytes = [Net.IPAddress]::Parse($Address).GetAddressBytes()
    $networkBytes = [Net.IPAddress]::Parse($cidrParts[0]).GetAddressBytes()
    if ($addressBytes.Count -ne 4 -or $networkBytes.Count -ne 4) {
        return $false
    }
    $wholeBytes = [Math]::Floor($prefixLength / 8)
    for ($index = 0; $index -lt $wholeBytes; $index++) {
        if ($addressBytes[$index] -ne $networkBytes[$index]) {
            return $false
        }
    }
    $remainingBits = $prefixLength % 8
    if ($remainingBits -eq 0) {
        return $true
    }
    $mask = 256 - [Math]::Pow(2, 8 - $remainingBits)
    return (
        ($addressBytes[$wholeBytes] -band [int]$mask) -eq
        ($networkBytes[$wholeBytes] -band [int]$mask)
    )
}

$existingRunners = @(Get-RepositoryRunners)
foreach ($existingRunner in $existingRunners | Where-Object { $_.name -like 'aci-entra-cba-*' }) {
    if ($existingRunner.status -ne 'offline' -or $existingRunner.busy) {
        throw "A prior lab runner '$($existingRunner.name)' is still active."
    }
    gh api `
        --method DELETE `
        "repos/$Repository/actions/runners/$($existingRunner.id)" `
        --silent
}

$existingContainers = @(
    az container list `
        --resource-group $infrastructure.resourceGroup `
        --output json | ConvertFrom-Json
) | Where-Object {
    $_.tags.workload -eq 'entra-cba-playwright' -and
    $_.tags.component -eq 'github-runner'
}
foreach ($existingContainer in $existingContainers) {
    $details = az container show `
        --name $existingContainer.name `
        --resource-group $infrastructure.resourceGroup `
        --output json | ConvertFrom-Json
    $currentState = $details.containers[0].instanceView.currentState.state
    $expiresAt = [DateTimeOffset]::MinValue
    $hasValidExpiry = [DateTimeOffset]::TryParse(
        [string]$details.tags.expiresAtUtc,
        [ref]$expiresAt
    )
    if ($currentState -notin @('Terminated', 'Failed') -and
        $hasValidExpiry -and
        $expiresAt -gt [DateTimeOffset]::UtcNow) {
        throw "A prior lab runner container '$($existingContainer.name)' is still active."
    }
    Remove-AciContainerGroup -Name $existingContainer.name
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
$expectedRunTitle = "Entra CBA POC $verificationId"
$runnerNameSuffix = if ($verificationId.Length -gt 16) {
    $verificationId.Substring(0, 8)
} else {
    $verificationId
}
$runnerName = "aci-entra-cba-$runnerNameSuffix"
$containerName = $runnerName
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
        expiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(
            $RegistrationTimeoutMinutes + $TimeoutMinutes + 10
        ).ToString('o')
        launcherId = $verificationId
        managedBy = 'script'
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

try {
    Invoke-RestMethod `
        -Method Put `
        -Uri $containerUri `
        -Headers $managementHeaders `
        -ContentType 'application/json' `
        -Body ($containerBody | ConvertTo-Json -Depth 20) | Out-Null
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
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $runnerStatePath -Encoding utf8NoBOM

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
        $currentState = $container.containers[0].instanceView.currentState
    } while (
        ($workflowRun.status -ne 'completed' -or $currentState.state -notin @('Terminated', 'Failed')) -and
        (Get-Date) -lt $completionDeadline
    )

    if ($workflowRun.status -ne 'completed' -or $currentState.state -notin @('Terminated', 'Failed')) {
        throw "Workflow or runner exceeded the $TimeoutMinutes-minute lifetime limit."
    }
    if ($currentState.exitCode -ne 0) {
        throw "Runner container exited with code '$($currentState.exitCode)'."
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

    $ciEvidenceDirectory = Join-Path $ciEvidenceRoot ([string]$workflowRun.id)
    if (Test-Path -LiteralPath $ciEvidenceDirectory) {
        Remove-Item -LiteralPath $ciEvidenceDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $ciEvidenceDirectory -Force | Out-Null

    $artifactDeadline = (Get-Date).AddSeconds(30)
    $expectedArtifactName = "entra-cba-playwright-$($workflowRun.id)"
    do {
        $artifacts = @(
            (gh api "repos/$Repository/actions/runs/$($workflowRun.id)/artifacts" | ConvertFrom-Json).artifacts
        ) | Where-Object { $_.name -ceq $expectedArtifactName }
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
            'verificationId',
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
            'verificationId',
            'verifiedAt'
        ) `
        -Label 'Runner network receipt'
    Assert-ExactProperties `
        -Object $networkReceipt.azure `
        -Expected @(
            'keyVaultHost',
            'keyVaultRead',
            'privateEndpointIp',
            'resolvedVaultIpv4Addresses',
            'runnerSubnetCidr'
        ) `
        -Label 'Runner network Azure evidence'
    Assert-ExactProperties `
        -Object $networkReceipt.github `
        -Expected @('oidcAudience', 'oidcIssuer', 'oidcSubject', 'repository', 'runId', 'sha') `
        -Label 'Runner network GitHub evidence'
    Assert-ExactProperties `
        -Object $networkReceipt.runner `
        -Expected @('architecture', 'environment', 'label', 'name', 'os', 'privateIpv4Addresses') `
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
    if ([int]$identityReceipt.schemaVersion -ne 2 -or
        $identityReceipt.verificationId -ne $verificationId -or
        [string]$identityReceipt.githubRunId -ne [string]$workflowRun.id -or
        $identityReceipt.githubSha -ne $workflowRun.head_sha -or
        $identityReceipt.identitySha256 -cne $expectedIdentitySha256) {
        throw 'The identity receipt does not match the exact workflow revision and lab identity.'
    }
    if ([int]$networkReceipt.schemaVersion -ne 1 -or
        $networkReceipt.verificationId -ne $verificationId -or
        $networkReceipt.receiptSha256 -notmatch '^[0-9a-f]{64}$' -or
        $networkReceipt.azure.keyVaultHost -cne "$($runnerNetwork.keyVaultName).vault.azure.net" -or
        $networkReceipt.azure.keyVaultRead -ne 'succeeded' -or
        $networkReceipt.azure.privateEndpointIp -ne $runnerNetwork.privateEndpointIp -or
        $networkReceipt.azure.runnerSubnetCidr -ne $runnerNetwork.runnerSubnetCidr -or
        @($networkReceipt.azure.resolvedVaultIpv4Addresses).Count -ne 1 -or
        $networkReceipt.azure.resolvedVaultIpv4Addresses[0] -ne $runnerNetwork.privateEndpointIp -or
        $networkReceipt.github.oidcAudience -ne 'api://AzureADTokenExchange' -or
        $networkReceipt.github.oidcIssuer -ne 'https://token.actions.githubusercontent.com' -or
        $networkReceipt.github.oidcSubject -cne $github.subject -or
        $networkReceipt.github.repository -cne $Repository -or
        [string]$networkReceipt.github.runId -ne [string]$workflowRun.id -or
        $networkReceipt.github.sha -ne $workflowRun.head_sha -or
        $networkReceipt.runner.environment -ne 'self-hosted' -or
        $networkReceipt.runner.label -cne $runnerLabel -or
        $networkReceipt.runner.name -cne $runnerName -or
        $networkReceipt.runner.os -ne 'Linux' -or
        $networkReceipt.runner.architecture -ne 'X64') {
        throw 'The runner network receipt does not match the exact ACI, OIDC, and Private Endpoint path.'
    }
    $runnerAddressesInSubnet = @($networkReceipt.runner.privateIpv4Addresses | Where-Object {
        Test-Ipv4AddressInCidr -Address $_ -Cidr $runnerNetwork.runnerSubnetCidr
    })
    if ($runnerAddressesInSubnet.Count -eq 0) {
        throw 'The CI receipt does not prove an ACI address in the delegated runner subnet.'
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
        Remove-AciContainerGroup -Name $containerName
    } catch {
        $cleanupErrors.Add("ACI deletion failed: $($_.Exception.Message)")
    }
    try {
        $runnerCleanupDeadline = (Get-Date).AddMinutes(2)
        $consecutiveRunnerAbsenceChecks = 0
        do {
            $runners = @(Get-RepositoryRunners)
            $matchingRunners = @($runners | Where-Object { $_.name -eq $runnerName })
            foreach ($runner in $matchingRunners) {
                gh api `
                    --method DELETE `
                    "repos/$Repository/actions/runners/$($runner.id)" `
                    --silent
            }
            if ($matchingRunners.Count -eq 0) {
                $consecutiveRunnerAbsenceChecks++
                if ($consecutiveRunnerAbsenceChecks -ge 3) {
                    break
                }
            } else {
                $consecutiveRunnerAbsenceChecks = 0
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $runnerCleanupDeadline)
        if ($consecutiveRunnerAbsenceChecks -lt 3) {
            throw "GitHub runner '$runnerName' was not verifiably deregistered."
        }
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
        $state.githubRunnerDeregistered = $true
        $state.workflowFinalConclusion = $cleanupWorkflowRun.conclusion
        $state.workflowFinalStatus = $cleanupWorkflowRun.status
        $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $runnerStatePath -Encoding utf8NoBOM
    }
}

Write-Host (
    "END_TO_END_VERIFIED runId=$($workflowRun.id) runner=$runnerName " +
    "privateEndpointIp=$($runnerNetwork.privateEndpointIp) receiptTransport=$evidenceTransport " +
    'conclusion=success cleanup=verified'
)
