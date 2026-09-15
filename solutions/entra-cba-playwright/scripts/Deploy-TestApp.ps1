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

$applicationCreated = $false
$servicePrincipalCreated = $false
try {
if (Test-Path $applicationStatePath) {
    $existingApplicationState = Get-Content $applicationStatePath -Raw | ConvertFrom-Json
    if ($existingApplicationState.tenantId -ne $infrastructure.tenantId -or
        $existingApplicationState.appUrl -ne $appUrl) {
        throw 'Existing application state does not match the deployed infrastructure.'
    }
    $application = [pscustomobject]@{
        appId = $existingApplicationState.appId
        displayName = $existingApplicationState.appDisplayName
        id = $existingApplicationState.appObjectId
    }
    $servicePrincipal = [pscustomobject]@{
        appId = $existingApplicationState.appId
        id = $existingApplicationState.servicePrincipalObjectId
    }
} else {
    $uniqueDisplayName = "$AppDisplayName [$([guid]::NewGuid().ToString('N').Substring(0, 8))]"
    $application = az ad app create `
        --display-name $uniqueDisplayName `
        --sign-in-audience AzureADMyOrg `
        --query '{appId:appId,id:id,displayName:displayName}' `
        --output json | ConvertFrom-Json
    $applicationCreated = $true

    $spaBody = @{
        spa = @{
            redirectUris = @($appUrl)
        }
    } | ConvertTo-Json -Depth 5 -Compress

    $spaBodyPath = Join-Path $stateDirectory 'spa-registration-patch.json'
    Set-Content -Path $spaBodyPath -Value $spaBody -Encoding utf8NoBOM
    try {
        az rest `
            --method PATCH `
            --url "https://graph.microsoft.com/v1.0/applications/$($application.id)" `
            --headers 'Content-Type=application/json' `
            --body "@$spaBodyPath" `
            --output none
    } finally {
        Remove-Item $spaBodyPath -Force -ErrorAction SilentlyContinue
    }

    $servicePrincipals = @(
        az ad sp list `
            --filter "appId eq '$($application.appId)'" `
            --query '[].{id:id,appId:appId}' `
            --output json | ConvertFrom-Json
    )

    if ($servicePrincipals.Count -eq 0) {
        $servicePrincipal = az ad sp create `
            --id $application.appId `
            --query '{id:id,appId:appId}' `
            --output json | ConvertFrom-Json
        $servicePrincipalCreated = $true
    } else {
        $servicePrincipal = $servicePrincipals[0]
    }
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
    servicePrincipalObjectId = $servicePrincipal.id
    staticWebAppName = $staticWebAppName
    testUsername = $TestUsername
    tenantId = $infrastructure.tenantId
}
$state | ConvertTo-Json -Depth 5 | Set-Content -Path $applicationStatePath -Encoding utf8NoBOM
} catch {
    $deploymentError = $_
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    if ($servicePrincipalCreated -and $servicePrincipal.id) {
        try {
            az ad sp delete --id $servicePrincipal.id
        } catch {
            $cleanupErrors.Add("Service principal cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($applicationCreated -and $application.id) {
        try {
            az ad app delete --id $application.id
        } catch {
            $cleanupErrors.Add("Application cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($cleanupErrors.Count -ne 0) {
        throw [InvalidOperationException]::new(
            "Application deployment failed and cleanup was incomplete: $($cleanupErrors -join ' | ')",
            $deploymentError.Exception
        )
    }
    throw $deploymentError
}

Write-Host "Test application deployed to $appUrl"
Write-Host "Application state: $applicationStatePath"
