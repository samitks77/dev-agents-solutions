[CmdletBinding()]
param(
    [string]$AppDisplayName = 'Entra CBA Playwright POC',
    [Parameter(Mandatory)][string]$TestUsername
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$infrastructureStatePath = Join-Path $stateDirectory 'infrastructure.json'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$applicationOperationStatePath = Join-Path $stateDirectory 'application-operation.json'
$applicationOperationLockPath = Join-Path $stateDirectory 'application-operation.lock'
$distributionDirectory = Join-Path $labRoot 'dist'
$toolDirectory = Join-Path $labRoot '.lab-tools'
$deploymentClientPath = Join-Path $toolDirectory 'StaticSitesClient.exe'
$deploymentClientUrl = 'https://swalocaldeployv2-bndtgugjgqc3dhdx.b01.azurefd.net/downloads/689a6c1fe8fc32f40348cc41223a7e9d83dd43d2/windows/StaticSitesClient.exe'
$deploymentClientSha256 = '58bc6533b9cbdd1d9564d3f36625308f4b20ec5a0c51b093cb35e4bf61545f82'

if (-not (Test-Path $infrastructureStatePath)) {
    throw "Infrastructure state not found at '$infrastructureStatePath'."
}

$infrastructure = Get-Content $infrastructureStatePath -Raw | ConvertFrom-Json
az account set --subscription $infrastructure.subscriptionId

$account = az account show -o json | ConvertFrom-Json
if ($account.tenantId -ne $infrastructure.tenantId) {
    throw 'The active Azure tenant does not match the infrastructure state.'
}

$appUrl = $infrastructure.outputs.appUrl.value
$staticWebAppName = $infrastructure.outputs.staticWebAppName.value

function Write-ApplicationStateAtomically {
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
            ($State | ConvertTo-Json -Depth 8),
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

function Get-ReconciledApplications {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [switch]$WaitForAppearance
    )

    $appearanceDeadline = (Get-Date).AddMinutes(10)
    $absenceDeadline = $appearanceDeadline.AddSeconds(30)
    $consecutiveAbsenceChecks = 0
    $escapedDisplayName = $DisplayName.Replace("'", "''")
    do {
        $applications = @(
            az ad app list `
                --filter "displayName eq '$escapedDisplayName'" `
                --query '[].{appId:appId,displayName:displayName,id:id,signInAudience:signInAudience,redirectUris:spa.redirectUris}' `
                --output json | ConvertFrom-Json
        )
        if ($applications.Count -ne 0 -or -not $WaitForAppearance) {
            return $applications
        }
        if ((Get-Date) -ge $appearanceDeadline) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return @()
            }
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $absenceDeadline)
    throw 'Application absence could not be proven after the appearance window.'
}

function Get-ReconciledServicePrincipals {
    param(
        [Parameter(Mandatory)][string]$AppId,
        [switch]$WaitForAppearance
    )

    $appearanceDeadline = (Get-Date).AddMinutes(10)
    $absenceDeadline = $appearanceDeadline.AddSeconds(30)
    $consecutiveAbsenceChecks = 0
    do {
        $servicePrincipals = @(
            az ad sp list `
                --filter "appId eq '$AppId'" `
                --query '[].{id:id,appId:appId}' `
                --output json | ConvertFrom-Json
        )
        if ($servicePrincipals.Count -ne 0 -or -not $WaitForAppearance) {
            return $servicePrincipals
        }
        if ((Get-Date) -ge $appearanceDeadline) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return @()
            }
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $absenceDeadline)
    throw 'Service-principal absence could not be proven after the appearance window.'
}

try {
    $applicationOperationLock = [IO.File]::Open(
        $applicationOperationLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another test-application deployment owns the exclusive local lock.'
}

try {
if (Test-Path -LiteralPath $applicationStatePath -PathType Leaf) {
    $existingApplicationState = Get-Content `
        -LiteralPath $applicationStatePath `
        -Raw | ConvertFrom-Json
    if ($existingApplicationState.tenantId -ne $infrastructure.tenantId -or
        $existingApplicationState.appUrl -ne $appUrl -or
        $existingApplicationState.testUsername -cne $TestUsername) {
        throw 'Existing application state does not match the deployed infrastructure.'
    }
    $application = az ad app show `
        --id $existingApplicationState.appObjectId `
        --query '{appId:appId,displayName:displayName,id:id,signInAudience:signInAudience,redirectUris:spa.redirectUris}' `
        --output json | ConvertFrom-Json
    $servicePrincipal = az ad sp show `
        --id $existingApplicationState.servicePrincipalObjectId `
        --query '{appId:appId,id:id}' `
        --output json | ConvertFrom-Json
    if (
        $application.id -ne $existingApplicationState.appObjectId -or
        $application.appId -ne $existingApplicationState.appId -or
        $application.displayName -cne $existingApplicationState.appDisplayName -or
        $application.signInAudience -ne 'AzureADMyOrg' -or
        @($application.redirectUris).Count -ne 1 -or
        $application.redirectUris[0] -cne $appUrl -or
        $servicePrincipal.id -ne $existingApplicationState.servicePrincipalObjectId -or
        $servicePrincipal.appId -ne $application.appId
    ) {
        throw 'The recorded application and service principal do not match live Entra objects.'
    }
}
else {
    $operation = if (
        Test-Path -LiteralPath $applicationOperationStatePath -PathType Leaf
    ) {
        Get-Content -LiteralPath $applicationOperationStatePath -Raw |
            ConvertFrom-Json -AsHashtable
    }
    else {
        $operationId = [guid]::NewGuid()
        [ordered]@{
            appDisplayName = "$AppDisplayName [$($operationId.ToString('N'))]"
            appId = $null
            appObjectId = $null
            appStatus = 'pending'
            appUrl = $appUrl
            operationId = $operationId.ToString('D')
            schemaVersion = 1
            servicePrincipalObjectId = $null
            servicePrincipalStatus = 'pending'
            spaStatus = 'pending'
            staticWebAppName = $staticWebAppName
            status = 'provisioning'
            testUsername = $TestUsername
            tenantId = $infrastructure.tenantId
        }
    }
    $operationId = [guid]::Empty
    if (
        [int]$operation.schemaVersion -ne 1 -or
        $operation.status -cne 'provisioning' -or
        -not [guid]::TryParseExact(
            [string]$operation.operationId,
            'D',
            [ref]$operationId
        ) -or
        $operation.appDisplayName -cne
            "$AppDisplayName [$($operationId.ToString('N'))]" -or
        $operation.tenantId -ine $infrastructure.tenantId -or
        $operation.appUrl -cne $appUrl -or
        $operation.staticWebAppName -cne $staticWebAppName -or
        $operation.testUsername -cne $TestUsername -or
        $operation.appStatus -notin @('pending', 'planned', 'created') -or
        $operation.spaStatus -notin @('pending', 'planned', 'verified') -or
        $operation.servicePrincipalStatus -notin @('pending', 'planned', 'created')
    ) {
        throw 'Application provisioning journal does not match the exact deployment contract.'
    }
    Write-ApplicationStateAtomically `
        -Path $applicationOperationStatePath `
        -State $operation

    $applications = @(Get-ReconciledApplications `
        -DisplayName $operation.appDisplayName `
        -WaitForAppearance:(
            $operation.appStatus -in @('planned', 'created')
        ))
    if ($applications.Count -gt 1) {
        throw 'More than one application matched the recovery-bound display name.'
    }
    if ($applications.Count -eq 0) {
        if ($operation.appObjectId -or $operation.appStatus -ceq 'created') {
            throw 'The exact journaled application no longer exists.'
        }
        $operation.appStatus = 'planned'
        Write-ApplicationStateAtomically `
            -Path $applicationOperationStatePath `
            -State $operation
        $application = az ad app create `
            --display-name $operation.appDisplayName `
            --sign-in-audience AzureADMyOrg `
            --query '{appId:appId,id:id,displayName:displayName,signInAudience:signInAudience,redirectUris:spa.redirectUris}' `
            --output json | ConvertFrom-Json
        if (-not $application.id -or -not $application.appId) {
            throw 'Application creation returned no identifiers; recovery state remains planned.'
        }
    }
    else {
        $application = $applications[0]
    }
    if (
        $application.displayName -cne $operation.appDisplayName -or
        $application.signInAudience -cne 'AzureADMyOrg' -or
        (
            $operation.appObjectId -and
            $application.id -ine $operation.appObjectId
        ) -or
        (
            $operation.appId -and
            $application.appId -ine $operation.appId
        )
    ) {
        throw 'The recovery-bound application has unexpected live properties.'
    }
    $operation.appId = $application.appId
    $operation.appObjectId = $application.id
    $operation.appStatus = 'created'
    Write-ApplicationStateAtomically `
        -Path $applicationOperationStatePath `
        -State $operation

    $spaBody = @{
        spa = @{
            redirectUris = @($appUrl)
        }
    } | ConvertTo-Json -Depth 5 -Compress

    $spaBodyPath = Join-Path $stateDirectory 'spa-registration-patch.json'
    $redirectUris = @($application.redirectUris)
    if ($redirectUris.Count -ne 1 -or $redirectUris[0] -cne $appUrl) {
        if ($redirectUris.Count -ne 0) {
            throw 'The recovery-bound application has unexpected SPA redirect URIs.'
        }
        $operation.spaStatus = 'planned'
        Write-ApplicationStateAtomically `
            -Path $applicationOperationStatePath `
            -State $operation
        Set-Content -Path $spaBodyPath -Value $spaBody -Encoding utf8NoBOM
        try {
            az rest `
                --method PATCH `
                --url "https://graph.microsoft.com/v1.0/applications/$($application.id)" `
                --headers 'Content-Type=application/json' `
                --body "@$spaBodyPath" `
                --output none
        }
        finally {
            Remove-Item $spaBodyPath -Force -ErrorAction SilentlyContinue
        }
    }
    $application = az ad app show `
        --id $operation.appObjectId `
        --query '{appId:appId,displayName:displayName,id:id,signInAudience:signInAudience,redirectUris:spa.redirectUris}' `
        --output json | ConvertFrom-Json
    if (
        $application.id -ine $operation.appObjectId -or
        $application.appId -ine $operation.appId -or
        $application.displayName -cne $operation.appDisplayName -or
        $application.signInAudience -cne 'AzureADMyOrg' -or
        @($application.redirectUris).Count -ne 1 -or
        $application.redirectUris[0] -cne $appUrl
    ) {
        throw 'Application redirect-URI read-back verification failed.'
    }
    $operation.spaStatus = 'verified'
    Write-ApplicationStateAtomically `
        -Path $applicationOperationStatePath `
        -State $operation

    $servicePrincipals = @(Get-ReconciledServicePrincipals `
        -AppId $application.appId `
        -WaitForAppearance:(
            $operation.servicePrincipalStatus -in @('planned', 'created')
        ))
    if ($servicePrincipals.Count -gt 1) {
        throw 'More than one service principal matched the journaled application ID.'
    }
    if ($servicePrincipals.Count -eq 0) {
        if (
            $operation.servicePrincipalObjectId -or
            $operation.servicePrincipalStatus -ceq 'created'
        ) {
            throw 'The exact journaled service principal no longer exists.'
        }
        $operation.servicePrincipalStatus = 'planned'
        Write-ApplicationStateAtomically `
            -Path $applicationOperationStatePath `
            -State $operation
        $servicePrincipal = az ad sp create `
            --id $application.appId `
            --query '{id:id,appId:appId}' `
            --output json | ConvertFrom-Json
        if (-not $servicePrincipal.id) {
            throw 'Service-principal creation returned no object ID; recovery state remains planned.'
        }
    }
    else {
        $servicePrincipal = $servicePrincipals[0]
    }
    if (
        $servicePrincipal.appId -ine $operation.appId -or
        (
            $operation.servicePrincipalObjectId -and
            $servicePrincipal.id -ine $operation.servicePrincipalObjectId
        )
    ) {
        throw 'The recovery-bound service principal has unexpected live properties.'
    }
    $operation.servicePrincipalObjectId = $servicePrincipal.id
    $operation.servicePrincipalStatus = 'created'
    Write-ApplicationStateAtomically `
        -Path $applicationOperationStatePath `
        -State $operation
}

Push-Location $labRoot
try {
    npm run build:app
} finally {
    Pop-Location
}

$runtimeConfiguration = "window.__CBA_CONFIG__ = $(@{
    clientId = $application.appId
    redirectUri = $appUrl
    tenantId = $infrastructure.tenantId
    testUsername = $TestUsername
} | ConvertTo-Json -Compress);"
Set-Content -Path (Join-Path $distributionDirectory 'config.js') -Value $runtimeConfiguration -Encoding utf8NoBOM

$deploymentToken = az staticwebapp secrets list `
    --name $staticWebAppName `
    --resource-group $infrastructure.resourceGroup `
    --query properties.apiKey `
    --output tsv

if (-not $deploymentToken) {
    throw 'Unable to obtain the Static Web Apps deployment token.'
}

New-Item -ItemType Directory -Path $toolDirectory -Force | Out-Null
if (-not (Test-Path $deploymentClientPath)) {
    Invoke-WebRequest -Uri $deploymentClientUrl -OutFile $deploymentClientPath
}

$actualClientHash = (Get-FileHash $deploymentClientPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualClientHash -ne $deploymentClientSha256) {
    throw 'The Static Sites deployment client checksum does not match the pinned SHA-256 value.'
}

$deploymentEnvironment = @{
    APP_LOCATION = $distributionDirectory
    CONFIG_FILE_LOCATION = $distributionDirectory
    DEPLOYMENT_ACTION = 'upload'
    DEPLOYMENT_PROVIDER = 'SwaCli'
    DEPLOYMENT_TOKEN = $deploymentToken
    FUNCTION_LANGUAGE = 'node'
    FUNCTION_LANGUAGE_VERSION = '22'
    SKIP_API_BUILD = 'true'
    SKIP_APP_BUILD = 'true'
    VERBOSE = 'false'
}

$deploymentEnvironment.GetEnumerator() | ForEach-Object {
    Set-Item -Path "Env:$($_.Key)" -Value $_.Value
}
try {
    & $deploymentClientPath
    if ($LASTEXITCODE -ne 0) {
        throw "Static Sites deployment client failed with exit code $LASTEXITCODE."
    }
} finally {
    $deploymentEnvironment.Keys | ForEach-Object {
        Remove-Item "Env:$_" -ErrorAction SilentlyContinue
    }
    $deploymentToken = $null
}

$response = Invoke-WebRequest -Uri $appUrl -Method Get
if ($response.StatusCode -ne 200) {
    throw "Application endpoint returned HTTP $($response.StatusCode)."
}

$state = [ordered]@{
    appDisplayName = $application.displayName
    appId = $application.appId
    appObjectId = $application.id
    appUrl = $appUrl
    applicationOwned = $true
    servicePrincipalObjectId = $servicePrincipal.id
    servicePrincipalOwned = $true
    schemaVersion = 2
    status = 'verified'
    staticWebAppName = $staticWebAppName
    testUsername = $TestUsername
    tenantId = $infrastructure.tenantId
}
Write-ApplicationStateAtomically -Path $applicationStatePath -State $state
if (Test-Path -LiteralPath $applicationOperationStatePath) {
    Remove-Item -LiteralPath $applicationOperationStatePath -Force
}
}
catch {
    if (
        -not (Test-Path -LiteralPath $applicationStatePath -PathType Leaf) -and
        (Test-Path -LiteralPath $applicationOperationStatePath -PathType Leaf)
    ) {
        throw [InvalidOperationException]::new(
            (
                'Application deployment was interrupted; exact app and service-principal ' +
                'recovery state was retained for a safe rerun.'
            ),
            $_.Exception
        )
    }
    throw
}
finally {
    $applicationOperationLock.Dispose()
}

Write-Host "Test application deployed to $appUrl"
Write-Host "Application state: $applicationStatePath"
