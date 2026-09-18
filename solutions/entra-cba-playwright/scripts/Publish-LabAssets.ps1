[CmdletBinding()]
param(
    [string]$PfxSecretName = 'cba-test-user-pfx',
    [string]$PassphraseSecretName = 'cba-test-user-pfx-passphrase',
    [string]$PublisherContainerName = 'aci-cba-secret-publisher',
    # Public immutable OCI digest, not a deployment credential.
    [string]$PublisherImage = 'mcr.microsoft.com/azure-cli@sha256:2d18d025d51e28e790855a8666fab5b7672f2aa62210bca3a75c1f3fd9b68e25'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($PublisherContainerName -notmatch '^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$') {
    throw "Publisher container prefix '$PublisherContainerName' is not a valid exact ACI name prefix."
}
if ($PublisherImage -notmatch '^mcr\.microsoft\.com/azure-cli@sha256:[a-f0-9]{64}$') {
    throw 'The privileged publisher image must use an immutable MCR SHA-256 digest.'
}

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$infrastructureStatePath = Join-Path $stateDirectory 'infrastructure.json'
$pkiStatePath = Join-Path $stateDirectory 'pki.json'
$credentialStatePath = Join-Path $stateDirectory 'credentials.json'
$publisherOperationStatePath = Join-Path $stateDirectory 'publisher-operation.json'
. (Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1')

function Write-PublisherOperationState {
    param([Parameter(Mandatory)][Collections.IDictionary]$State)

    $operationId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$publisherOperationStatePath.$operationId.tmp"
    $backupPath = "$publisherOperationStatePath.$operationId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($State | ConvertTo-Json -Depth 5),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $publisherOperationStatePath) {
            [IO.File]::Replace(
                $temporaryPath,
                $publisherOperationStatePath,
                $backupPath,
                $true
            )
        }
        else {
            [IO.File]::Move($temporaryPath, $publisherOperationStatePath)
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

foreach ($requiredPath in @($infrastructureStatePath, $pkiStatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

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
    throw 'Another credential publisher operation already owns the exclusive local lock.'
}

try {
$infrastructure = Get-Content -LiteralPath $infrastructureStatePath -Raw | ConvertFrom-Json

az account set --subscription $infrastructure.subscriptionId
$azureAccount = az account show --output json | ConvertFrom-Json
if ($azureAccount.id -ne $infrastructure.subscriptionId -or
    $azureAccount.tenantId -ne $infrastructure.tenantId) {
    throw 'Azure CLI context does not match the stored subscription and tenant.'
}
$resourceGroup = $infrastructure.resourceGroup
$vaultName = $infrastructure.outputs.runnerVaultName.value
$vault = az keyvault show --name $vaultName --resource-group $resourceGroup --output json | ConvertFrom-Json
if ($vault.properties.publicNetworkAccess -ne 'Disabled') {
    throw "Key Vault '$vaultName' is expected to use private-only network access."
}
if ($vault.properties.enableRbacAuthorization -ne $true) {
    throw "Key Vault '$vaultName' must use Azure RBAC authorization, not access policies."
}

$runnerSubnetId = $infrastructure.outputs.runnerSubnetId.value
$publisherClientId = $infrastructure.outputs.publisherClientId.value
$publisherPrincipalId = $infrastructure.outputs.publisherPrincipalId.value
$publisherResourceId = $infrastructure.outputs.publisherResourceId.value
foreach ($requiredValue in @($runnerSubnetId, $publisherClientId, $publisherPrincipalId, $publisherResourceId)) {
    if (-not $requiredValue) {
        throw 'Infrastructure state does not contain the private runner network and publisher identity outputs.'
    }
}

# Public Azure built-in Key Vault Secrets Officer role definition ID.
$secretsOfficerRoleDefinitionId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

$recordedPublisherAssignmentId = Get-RecordedPublisherAssignmentId `
    -OperationStatePath $publisherOperationStatePath `
    -PublisherPrincipalId $publisherPrincipalId `
    -VaultResourceId $vault.id
if ($recordedPublisherAssignmentId) {
    $recordedPublisherOperation = Get-Content `
        -LiteralPath $publisherOperationStatePath `
        -Raw | ConvertFrom-Json
    Remove-ExactPublisherAssignment `
        -AssignmentId $recordedPublisherAssignmentId `
        -PrincipalId $publisherPrincipalId `
        -VaultResourceId $vault.id `
        -RoleDefinitionId $secretsOfficerRoleDefinitionId `
        -RequireAppearanceWindow
    if ($recordedPublisherOperation.containerName) {
        if (
            $recordedPublisherOperation.containerName -cne $PublisherContainerName -or
            $recordedPublisherOperation.operationId -cne
                $recordedPublisherOperation.assignmentName
        ) {
            throw 'Publisher operation has invalid cloud-container ownership state.'
        }
        Remove-ExactPublisherContainerGroup `
            -Name $recordedPublisherOperation.containerName `
            -OperationId $recordedPublisherOperation.operationId `
            -ResourceGroup $resourceGroup `
            -RequireAppearanceWindow
    }
    Remove-Item -LiteralPath $publisherOperationStatePath -Force
}
else {
    $publisherMutationAssignments = @(Get-KeyVaultSecretMutationCapabilityAssignments `
        -PrincipalId $publisherPrincipalId `
        -VaultResourceId $vault.id)
}
if (-not $recordedPublisherAssignmentId -and $publisherMutationAssignments.Count -ne 0) {
    $roleSummary = $publisherMutationAssignments | ForEach-Object {
        "'$($_.roleName)' at '$($_.scope)'"
    }
    throw (
        'The publisher identity has unrecorded direct or self-elevatable secret-mutation ' +
        'access that this script will not ' +
        "delete: $($roleSummary -join ', ')."
    )
}

$stalePublisherContainers = @(
    @(
        az container list `
            --resource-group $resourceGroup `
            --output json | ConvertFrom-Json
    ) | Where-Object {
        $isCurrentPublisher = (
            $_.tags.component -eq 'credential-publisher' -and
            $_.tags.managedBy -eq 'script'
        )
        $isLegacyDefaultPublisher = (
            $PublisherContainerName -ceq 'aci-cba-secret-publisher' -and
            -not $_.tags.component -and
            $_.name -like 'aci-cba-secret-publisher-*' -and
            $_.tags.managedBy -eq 'script'
        )
        (
            $_.name -ceq $PublisherContainerName -or
            $_.name -like "$PublisherContainerName-*"
        ) -and
        $_.tags.workload -eq 'entra-cba-playwright' -and
        ($isCurrentPublisher -or $isLegacyDefaultPublisher)
    }
)
if ($stalePublisherContainers.Count -ne 0) {
    $containerNames = @($stalePublisherContainers.name | Sort-Object -CaseSensitive)
    throw (
        'Existing publisher containers are not owned by this local operation and were not ' +
        "deleted: $($containerNames -join ', '). Review their exact cloud state first."
    )
}

$pki = Get-Content -LiteralPath $pkiStatePath -Raw | ConvertFrom-Json
$mfaCertificates = @($pki.certificates | Where-Object {
    $_.name -eq 'cba-playwright-test-mfa'
})
if ($mfaCertificates.Count -ne 1) {
    throw 'Expected exactly one multifactor test certificate in PKI state.'
}
$mfaCertificate = $mfaCertificates[0]

$passphrase = Import-Clixml -LiteralPath $pki.pfxPassphrasePath
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passphrase)
try {
    $plainPassphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $passphrase = $null
}

$pfxBase64 = [Convert]::ToBase64String(
    [IO.File]::ReadAllBytes($mfaCertificate.pfxPath)
)
if ([Text.Encoding]::UTF8.GetByteCount($pfxBase64) -gt 24000) {
    throw 'The base64-encoded PFX is too large for the configured Key Vault secret limit.'
}

$publisherScript = @'
set -eu
umask 077
login_attempt=1
until az login --identity --username "$CLIENT_ID" --allow-no-subscriptions --output none; do
  if [ "$login_attempt" -ge 12 ]; then
    exit 1
  fi
  login_attempt=$((login_attempt + 1))
  sleep 10
done
printf "%s" "$PFX_BASE64" > /tmp/cba-pfx.txt
printf "%s" "$PFX_PASSPHRASE" > /tmp/cba-passphrase.txt
set_secret() {
  secret_name="$1"
  secret_file="$2"
  content_type="$3"
  credential_tag="$4"
  attempt=1
  while true; do
    if secret_id=$(az keyvault secret set --vault-name "$VAULT_NAME" --name "$secret_name" --file "$secret_file" --encoding utf-8 --content-type "$content_type" --expires "$EXPIRES_ON" --tags purpose=entra-cba-playwright-poc credential="$credential_tag" --query id --output tsv --only-show-errors); then
      printf "%s" "$secret_id"
      return 0
    fi
    if [ "$attempt" -ge 12 ]; then
      return 1
    fi
    attempt=$((attempt + 1))
    sleep 10
  done
}
pfx_id=$(set_secret "$PFX_SECRET_NAME" /tmp/cba-pfx.txt application/x-pkcs12-base64 test-user-pfx)
passphrase_id=$(set_secret "$PASSPHRASE_SECRET_NAME" /tmp/cba-passphrase.txt text/plain test-user-pfx-passphrase)
stored_pfx=$(az keyvault secret show --vault-name "$VAULT_NAME" --name "$PFX_SECRET_NAME" --query value --output tsv --only-show-errors)
stored_passphrase=$(az keyvault secret show --vault-name "$VAULT_NAME" --name "$PASSPHRASE_SECRET_NAME" --query value --output tsv --only-show-errors)
[ "$stored_pfx" = "$PFX_BASE64" ]
[ "$stored_passphrase" = "$PFX_PASSPHRASE" ]
rm -f /tmp/cba-pfx.txt /tmp/cba-passphrase.txt
unset PFX_BASE64 PFX_PASSPHRASE stored_pfx stored_passphrase
printf "PFX_SECRET_ID=%s\n" "$pfx_id"
printf "PASSPHRASE_SECRET_ID=%s\n" "$passphrase_id"
printf "ROUNDTRIP_VERIFIED\n"
printf "PUBLISH_SUCCEEDED\n"
'@
$publisherScript = $publisherScript.Replace("`r`n", "`n")

$publisherAssignmentName = [guid]::NewGuid().ToString()
$publisherAssignmentId = (
    "$($vault.id)/providers/Microsoft.Authorization/roleAssignments/" +
    $publisherAssignmentName
)
$managementToken = $null
$publisherAssignment = $null
$pfxSecretId = $null
$passphraseSecretId = $null
$effectiveContainerName = $PublisherContainerName
$publisherOperation = [ordered]@{
    assignmentId = $publisherAssignmentId
    assignmentName = $publisherAssignmentName
    containerName = $effectiveContainerName
    containerStatus = 'pending'
    operationId = $publisherAssignmentName
    publisherPrincipalId = $publisherPrincipalId
    roleDefinitionId = $secretsOfficerRoleDefinitionId
    schemaVersion = 1
    startedAt = [DateTimeOffset]::UtcNow.ToString('o')
    status = 'planned'
    vaultId = $vault.id
}
Write-PublisherOperationState -State $publisherOperation

try {
    $publisherAssignment = az role assignment create `
        --name $publisherAssignmentName `
        --assignee-object-id $publisherPrincipalId `
        --assignee-principal-type ServicePrincipal `
        --role $secretsOfficerRoleDefinitionId `
        --scope $vault.id `
        --output json | ConvertFrom-Json
    if (
        $publisherAssignment.id -ine $publisherAssignmentId -or
        $publisherAssignment.principalId -ine $publisherPrincipalId -or
        $publisherAssignment.scope -ine $vault.id -or
        (Split-Path -Leaf $publisherAssignment.roleDefinitionId) -ine
            $secretsOfficerRoleDefinitionId
    ) {
        throw 'Azure returned unexpected publisher role-assignment properties.'
    }
    $publisherOperation.status = 'created'
    Write-PublisherOperationState -State $publisherOperation

    $expiresOn = [DateTime]::Parse($mfaCertificate.notAfter).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $userAssignedIdentities = @{}
    $userAssignedIdentities[$publisherResourceId] = @{}
    $containerBody = @{
        identity = @{
            type = 'UserAssigned'
            userAssignedIdentities = $userAssignedIdentities
        }
        location = $infrastructure.location
        properties = @{
            containers = @(
                @{
                    name = 'publisher'
                    properties = @{
                        command = @('/bin/sh', '-c', $publisherScript)
                        environmentVariables = @(
                            @{ name = 'CLIENT_ID'; value = $publisherClientId }
                            @{ name = 'EXPIRES_ON'; value = $expiresOn }
                            @{ name = 'PASSPHRASE_SECRET_NAME'; value = $PassphraseSecretName }
                            @{ name = 'PFX_BASE64'; secureValue = $pfxBase64 }
                            @{ name = 'PFX_PASSPHRASE'; secureValue = $plainPassphrase }
                            @{ name = 'PFX_SECRET_NAME'; value = $PfxSecretName }
                            @{ name = 'VAULT_NAME'; value = $vaultName }
                        )
                        image = $PublisherImage
                        resources = @{
                            requests = @{
                                cpu = 1
                                memoryInGB = 1.5
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
            component = 'credential-publisher'
            environment = 'poc'
            expiresAtUtc = [DateTimeOffset]::UtcNow.AddMinutes(15).ToString('o')
            managedBy = 'script'
            operationId = $publisherAssignmentName
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
    $managementHeaders['If-None-Match'] = '*'
    $containerUri = (
        "https://management.azure.com/subscriptions/$($infrastructure.subscriptionId)" +
        "/resourceGroups/$resourceGroup/providers/Microsoft.ContainerInstance" +
        "/containerGroups/$effectiveContainerName`?api-version=2023-05-01"
    )
    $publisherOperation.containerStatus = 'planned'
    Write-PublisherOperationState -State $publisherOperation
    $createdContainer = Invoke-RestMethod `
        -Method Put `
        -Uri $containerUri `
        -Headers $managementHeaders `
        -ContentType 'application/json' `
        -Body ($containerBody | ConvertTo-Json -Depth 20)
    if (
        $createdContainer.name -cne $effectiveContainerName -or
        $createdContainer.tags.operationId -cne $publisherAssignmentName
    ) {
        throw 'Azure did not grant the exact create-only publisher container lease.'
    }
    $publisherOperation.containerStatus = 'created'
    Write-PublisherOperationState -State $publisherOperation

    $deadline = (Get-Date).AddMinutes(10)
    do {
        Start-Sleep -Seconds 10
        $container = az container show `
            --name $effectiveContainerName `
            --resource-group $resourceGroup `
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
            $container.provisioningState -ne 'Succeeded' -or
            $currentStateName -notin @('Terminated', 'Failed')
        ) -and
        (Get-Date) -lt $deadline
    )

    if ($container.provisioningState -ne 'Succeeded' -or
        $currentStateName -notin @('Terminated', 'Failed')) {
        throw (
            "Credential publisher did not finish within ten minutes; provisioning is " +
            "'$($container.provisioningState)' and runtime state is '$currentStateName'."
        )
    }
    if (@($container.containers).Count -ne 1 -or
        $container.containers[0].image -cne $PublisherImage) {
        throw 'The credential publisher did not run the exact digest-pinned image.'
    }

    $publisherLogs = $null
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            $publisherLogs = (az container logs `
                --name $effectiveContainerName `
                --resource-group $resourceGroup) -join [Environment]::NewLine
            break
        } catch {
            if ($attempt -eq 6) {
                throw
            }
            Start-Sleep -Seconds 5
        }
    }
    $exitCode = if ($null -ne $currentState) {
        $currentState.exitCode
    } else {
        $null
    }
    if ($null -eq $exitCode -or $exitCode -ne 0 -or
        $publisherLogs -notmatch '\bROUNDTRIP_VERIFIED\b' -or
        $publisherLogs -notmatch '\bPUBLISH_SUCCEEDED\b') {
        throw "Credential publisher failed with state '$currentStateName' and exit code '$exitCode': $publisherLogs"
    }

    $pfxSecretId = [regex]::Match($publisherLogs, 'PFX_SECRET_ID=(\S+)').Groups[1].Value
    $passphraseSecretId = [regex]::Match(
        $publisherLogs,
        'PASSPHRASE_SECRET_ID=(\S+)'
    ).Groups[1].Value
    if (-not $pfxSecretId -or -not $passphraseSecretId) {
        throw 'Credential publisher did not return both Key Vault secret IDs.'
    }
} finally {
    $plainPassphrase = $null
    $pfxBase64 = $null
    $containerBody = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        Remove-ExactPublisherAssignment `
            -AssignmentId $publisherAssignmentId `
            -PrincipalId $publisherPrincipalId `
            -VaultResourceId $vault.id `
            -RoleDefinitionId $secretsOfficerRoleDefinitionId `
            -RequireAppearanceWindow:($publisherOperation.status -ne 'created') `
            -ConfirmedLiveAssignment:($publisherOperation.status -eq 'created')
    }
    catch {
        $cleanupErrors.Add("Publisher access verification failed: $($_.Exception.Message)")
    }
    try {
        if ($publisherOperation.containerStatus -ne 'pending') {
            Remove-ExactPublisherContainerGroup `
                -Name $effectiveContainerName `
                -OperationId $publisherAssignmentName `
                -ResourceGroup $resourceGroup `
                -RequireAppearanceWindow
        }
    }
    catch {
        $cleanupErrors.Add("ACI deletion failed: $($_.Exception.Message)")
    }
    if ($cleanupErrors.Count -eq 0) {
        Remove-Item -LiteralPath $publisherOperationStatePath -Force
    }
    $managementHeaders = $null
    $managementToken = $null
    if ($cleanupErrors.Count -ne 0) {
        throw "Publisher cleanup failed: $($cleanupErrors -join ' | ')"
    }
}

& (Join-Path $PSScriptRoot 'Test-PublishedCrl.ps1')

$credentialState = [ordered]@{
    passphraseSecretId = $passphraseSecretId
    passphraseSecretName = $PassphraseSecretName
    pfxSecretId = $pfxSecretId
    pfxSecretName = $PfxSecretName
    publishedAt = (Get-Date).ToString('o')
    publishingPath = 'private-aci'
    vaultName = $vaultName
}
$credentialState | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $credentialStatePath -Encoding utf8NoBOM

Write-Host "Public CRL is reachable at $($pki.crlUrl)"
Write-Host "The private runner vault contains the PFX and passphrase as separate secrets."
}
finally {
    $publisherLockStream.Dispose()
}
