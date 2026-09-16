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
. (Join-Path $PSScriptRoot 'KeyVault-Rbac.ps1')

foreach ($requiredPath in @($infrastructureStatePath, $pkiStatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

$infrastructure = Get-Content -LiteralPath $infrastructureStatePath -Raw | ConvertFrom-Json
$pki = Get-Content -LiteralPath $pkiStatePath -Raw | ConvertFrom-Json
$mfaCertificates = @($pki.certificates | Where-Object { $_.name -eq 'cba-playwright-test-mfa' })
if ($mfaCertificates.Count -ne 1) {
    throw 'Expected exactly one multifactor test certificate in PKI state.'
}
$mfaCertificate = $mfaCertificates[0]

$passphrase = Import-Clixml -LiteralPath $pki.pfxPassphrasePath
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passphrase)
try {
    $plainPassphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $passphrase = $null
}

$pfxBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($mfaCertificate.pfxPath))
if ([Text.Encoding]::UTF8.GetByteCount($pfxBase64) -gt 24000) {
    throw 'The base64-encoded PFX is too large for the configured Key Vault secret limit.'
}

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

function Remove-PublisherContainerGroup {
    param([Parameter(Mandatory)][string]$Name)

    $deletionDeadline = (Get-Date).AddMinutes(5)
    $consecutiveAbsenceChecks = 0
    do {
        $existingContainer = az container list `
            --resource-group $resourceGroup `
            --query "[?name=='$Name'].name | [0]" `
            --output tsv
        if ($existingContainer) {
            $consecutiveAbsenceChecks = 0
            az container delete `
                --name $Name `
                --resource-group $resourceGroup `
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

    throw "Publisher container '$Name' was not verifiably absent after deletion."
}

$stalePublisherContainers = @(
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
    $_.name -like "$PublisherContainerName-*" -and
    $_.tags.workload -eq 'entra-cba-playwright' -and
    ($isCurrentPublisher -or $isLegacyDefaultPublisher)
}
foreach ($staleContainer in $stalePublisherContainers) {
    Remove-PublisherContainerGroup -Name $staleContainer.name
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
$publisherMutationAssignments = @(Get-KeyVaultSecretMutationAssignments `
    -PrincipalId $publisherPrincipalId `
    -VaultResourceId $vault.id)
$directStaleAssignments = @($publisherMutationAssignments | Where-Object {
    $_.scope -eq $vault.id -or
    ([string]$_.scope).StartsWith("$($vault.id)/", [StringComparison]::OrdinalIgnoreCase)
})
foreach ($assignment in $directStaleAssignments) {
    az role assignment delete --ids $assignment.assignmentId --output none
}
if ($directStaleAssignments.Count -ne 0) {
    $revocationDeadline = (Get-Date).AddMinutes(2)
    do {
        $publisherMutationAssignments = @(Get-KeyVaultSecretMutationAssignments `
            -PrincipalId $publisherPrincipalId `
            -VaultResourceId $vault.id)
        if ($publisherMutationAssignments.Count -ne 0) {
            Start-Sleep -Seconds 5
        }
    } while ($publisherMutationAssignments.Count -ne 0 -and (Get-Date) -lt $revocationDeadline)
}
if ($publisherMutationAssignments.Count -ne 0) {
    $roleSummary = $publisherMutationAssignments | ForEach-Object {
        "'$($_.roleName)' at '$($_.scope)'"
    }
    throw "The publisher identity retains secret-mutation access through $($roleSummary -join ', ')."
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
$roleCreationAttempted = $false
$containerCreationAttempted = $false
$managementToken = $null
$publisherAssignment = $null
$pfxSecretId = $null
$passphraseSecretId = $null
$effectiveContainerName = "$PublisherContainerName-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"

try {
    $roleCreationAttempted = $true
    $publisherAssignment = az role assignment create `
        --name $publisherAssignmentName `
        --assignee-object-id $publisherPrincipalId `
        --assignee-principal-type ServicePrincipal `
        --role $secretsOfficerRoleDefinitionId `
        --scope $vault.id `
        --output json | ConvertFrom-Json
    if ($publisherAssignment.id -ine $publisherAssignmentId) {
        throw 'Azure returned an unexpected publisher role-assignment identity.'
    }

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
        "/resourceGroups/$resourceGroup/providers/Microsoft.ContainerInstance" +
        "/containerGroups/$effectiveContainerName`?api-version=2023-05-01"
    )
    $containerCreationAttempted = $true
    Invoke-RestMethod `
        -Method Put `
        -Uri $containerUri `
        -Headers $managementHeaders `
        -ContentType 'application/json' `
        -Body ($containerBody | ConvertTo-Json -Depth 20) | Out-Null

    $deadline = (Get-Date).AddMinutes(10)
    do {
        Start-Sleep -Seconds 10
        $container = az container show `
            --name $effectiveContainerName `
            --resource-group $resourceGroup `
            --output json | ConvertFrom-Json
        $currentState = $container.containers[0].instanceView.currentState
    } while (
        (
            $container.provisioningState -ne 'Succeeded' -or
            $currentState.state -notin @('Terminated', 'Failed')
        ) -and
        (Get-Date) -lt $deadline
    )

    if ($container.provisioningState -ne 'Succeeded' -or
        $currentState.state -notin @('Terminated', 'Failed')) {
        throw (
            "Credential publisher did not finish within ten minutes; provisioning is " +
            "'$($container.provisioningState)' and runtime state is '$($currentState.state)'."
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
    if ($currentState.exitCode -ne 0 -or
        $publisherLogs -notmatch '\bROUNDTRIP_VERIFIED\b' -or
        $publisherLogs -notmatch '\bPUBLISH_SUCCEEDED\b') {
        throw "Credential publisher failed with state '$($currentState.state)' and exit code '$($currentState.exitCode)': $publisherLogs"
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
        if ($containerCreationAttempted) {
            Remove-PublisherContainerGroup -Name $effectiveContainerName
        }
    } catch {
        $cleanupErrors.Add("ACI deletion failed: $($_.Exception.Message)")
    }
    try {
        $revocationDeadline = (Get-Date).AddMinutes(2)
        $lastRevocationError = $null
        do {
            $targetAssignments = @()
            try {
                $remainingPublisherAccess = @(
                    Get-KeyVaultSecretMutationAssignments `
                        -PrincipalId $publisherPrincipalId `
                        -VaultResourceId $vault.id
                )
                $lastRevocationError = $null
                $targetAssignments = @(
                    $remainingPublisherAccess | Where-Object {
                        $_.assignmentId -ieq $publisherAssignmentId
                    }
                )
                if ($targetAssignments.Count -gt 1) {
                    throw 'Azure returned duplicate exact publisher role assignments.'
                }
                if ($targetAssignments.Count -eq 1) {
                    az role assignment delete `
                        --ids $publisherAssignmentId `
                        --output none
                }
                $lastRevocationError = $null
            } catch {
                $lastRevocationError = $_
            }
            if ($targetAssignments.Count -ne 0 -or $lastRevocationError) {
                Start-Sleep -Seconds 5
            }
        } while (
            ($targetAssignments.Count -ne 0 -or $lastRevocationError) -and
            (Get-Date) -lt $revocationDeadline
        )
        $remainingPublisherAccess = @(
            Get-KeyVaultSecretMutationAssignments `
                -PrincipalId $publisherPrincipalId `
                -VaultResourceId $vault.id
        )
        if ($remainingPublisherAccess.Count -ne 0) {
            throw 'The publisher identity still has secret-mutation access.'
        }
        if ($lastRevocationError) {
            throw $lastRevocationError
        }
    } catch {
        $cleanupErrors.Add("Publisher access verification failed: $($_.Exception.Message)")
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
