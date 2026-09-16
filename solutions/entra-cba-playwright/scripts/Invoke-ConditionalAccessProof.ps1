[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateSet('Both', 'Negative')][string]$BrowserScenario = 'Both',
    [ValidateRange(5, 60)][int]$EvidenceTimeoutMinutes = 30,
    [Parameter(Mandatory)][string]$InterferingPolicyIdsCsv,
    [switch]$ConfirmExclusiveConditionalAccessWindow,
    [switch]$RestoreIsolationOnly,
    [ValidateRange(30, 300)][int]$NegativeFinalizationSeconds = 120,
    [ValidateRange(30, 1800)][int]$PropagationSeconds = 120
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$requiredScopes = @(
    'Application.Read.All',
    'AuditLog.Read.All',
    'Policy.Read.All',
    'Policy.ReadWrite.ConditionalAccess'
)
# Public Microsoft Graph PowerShell first-party application ID.
$graphPowerShellClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$scope = ($requiredScopes + @('offline_access', 'openid', 'profile')) -join ' '

function Connect-ValidatedGraphDeviceCode {
    $deviceCodeResponse = Invoke-RestMethod `
        -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            client_id = $graphPowerShellClientId
            scope = $scope
        }
    Write-Host (
        "DEVICE_AUTH_REQUIRED uri=$($deviceCodeResponse.verification_uri) " +
        "code=$($deviceCodeResponse.user_code) " +
        "expiresInSeconds=$($deviceCodeResponse.expires_in)"
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
        [int]$deviceCodeResponse.expires_in
    )
    $intervalSeconds = [Math]::Max([int]$deviceCodeResponse.interval, 5)
    $tokenResponse = $null
    do {
        Start-Sleep -Seconds $intervalSeconds
        try {
            $tokenResponse = Invoke-RestMethod `
                -Method Post `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{
                    client_id = $graphPowerShellClientId
                    device_code = $deviceCodeResponse.device_code
                    grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
                }
        } catch {
            $details = $null
            if ($_.ErrorDetails.Message) {
                try {
                    $details = $_.ErrorDetails.Message | ConvertFrom-Json
                } catch {
                    $details = $null
                }
            }
            if ($details.error -eq 'authorization_pending') {
                continue
            }
            if ($details.error -eq 'slow_down') {
                $intervalSeconds += 5
                continue
            }
            if ($_.FullyQualifiedErrorId -match 'ResponseEnded' -or
                $_.Exception.Message -match 'response ended prematurely') {
                Write-Warning 'Device-token polling response ended early; retrying within the authorization window.'
                continue
            }
            $statusCode = if ($_.Exception.Response -and
                $null -ne $_.Exception.Response.StatusCode) {
                [int]$_.Exception.Response.StatusCode
            } else {
                $null
            }
            if ($null -ne $statusCode -and $statusCode -ge 500 -and $statusCode -lt 600) {
                Write-Warning (
                    "Device-token polling returned transient HTTP $statusCode; " +
                    'retrying within the authorization window.'
                )
                continue
            }
            if ($details) {
                throw (
                    "Device authorization failed: $($details.error): " +
                    $details.error_description
                )
            }
            throw
        }
    } while (-not $tokenResponse -and [DateTimeOffset]::UtcNow -lt $deadline)

    if (-not $tokenResponse.access_token) {
        throw 'Device authorization expired without an access token.'
    }
    $accessToken = [string]$tokenResponse.access_token
    $tokenResponse = $null
    $deviceCodeResponse = $null

    $tokenParts = $accessToken.Split('.')
    if ($tokenParts.Count -ne 3) {
        throw 'Graph access token is not a JWT.'
    }
    $payload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }
    $claims = (
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) |
            ConvertFrom-Json
    )
    $grantedScopes = @(
        ([string]$claims.scp).Split(
            ' ',
            [StringSplitOptions]::RemoveEmptyEntries
        )
    )
    $missingScopes = @(
        $requiredScopes | Where-Object { $_ -notin $grantedScopes }
    )
    # Public Microsoft Graph resource application ID and documented URI audiences.
    $validAudiences = @(
        '00000003-0000-0000-c000-000000000000',
        'https://graph.microsoft.com',
        'https://graph.microsoft.com/'
    )
    $tokenExpiresAt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$claims.exp)
    $tokenClientId = if ($claims.azp) { $claims.azp } else { $claims.appid }
    if ($claims.tid -ne $TenantId -or
        $claims.aud -notin $validAudiences -or
        $tokenClientId -ne $graphPowerShellClientId -or
        $missingScopes.Count -ne 0 -or
        $tokenExpiresAt -le [DateTimeOffset]::UtcNow) {
        throw "Graph token validation failed; missing scopes: $($missingScopes -join ', ')."
    }

    Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
    $secureToken = ConvertTo-SecureString $accessToken -AsPlainText -Force
    $accessToken = $null
    try {
        Connect-MgGraph `
            -AccessToken $secureToken `
            -ClientTimeout 30 `
            -NoWelcome
    } finally {
        $secureToken = $null
    }

    $context = Get-MgContext
    $contextMissingScopes = @(
        $requiredScopes | Where-Object { $_ -notin @($context.Scopes) }
    )
    if (-not $context -or
        $context.TenantId -ne $TenantId -or
        $contextMissingScopes.Count -ne 0) {
        throw (
            'Graph context validation failed; missing scopes: ' +
            "$($contextMissingScopes -join ', ')."
        )
    }
    Write-Host "GRAPH_CONTEXT_VERIFIED tenant=$($context.TenantId)"
    return $tokenExpiresAt
}

function Set-ManagedPolicyReportOnly {
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][string]$PolicyDisplayName,
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$AuthenticationStrengthId
    )

    $policyUri = (
        'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/' +
        $PolicyId
    )
    Invoke-MgGraphRequest `
        -Method PATCH `
        -Uri $policyUri `
        -Body (@{
            state = 'enabledForReportingButNotEnforced'
        } | ConvertTo-Json) `
        -ContentType 'application/json' | Out-Null

    $deadline = (Get-Date).AddMinutes(2)
    $verifiedPolicy = $null
    do {
        Start-Sleep -Seconds 5
        $verifiedPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
    } while (
        $verifiedPolicy.state -ne 'enabledForReportingButNotEnforced' -and
        (Get-Date) -lt $deadline
    )

    if ($verifiedPolicy.id -ne $PolicyId -or
        $verifiedPolicy.displayName -cne $PolicyDisplayName -or
        $verifiedPolicy.state -ne 'enabledForReportingButNotEnforced' -or
        @($verifiedPolicy.conditions.users.includeGroups).Count -ne 1 -or
        $verifiedPolicy.conditions.users.includeGroups[0] -ne $GroupId -or
        @($verifiedPolicy.conditions.applications.includeApplications).Count -ne 1 -or
        $verifiedPolicy.conditions.applications.includeApplications[0] -ne $ApplicationId -or
        $verifiedPolicy.grantControls.authenticationStrength.id -ne
            $AuthenticationStrengthId) {
        throw 'Fallback report-only restoration did not verify the exact managed policy.'
    }
}

function Restore-LabPolicyReportOnly {
    param(
        [Parameter(Mandatory)][object]$PolicyState,
        [Parameter(Mandatory)][string]$ConfigureScript
    )

    try {
        & $ConfigureScript `
            -TenantId $TenantId `
            -State enabledForReportingButNotEnforced
        Write-Host 'CA_PHASE=REPORT_ONLY_RESTORED'
    } catch {
        $primaryRestoreError = $_
        try {
            Set-ManagedPolicyReportOnly `
                -PolicyId $PolicyState.policyId `
                -PolicyDisplayName $PolicyState.policyDisplayName `
                -GroupId $PolicyState.groupId `
                -ApplicationId $PolicyState.applicationId `
                -AuthenticationStrengthId $PolicyState.authenticationStrengthId
            Write-Host 'CA_PHASE=REPORT_ONLY_RESTORED_BY_FALLBACK'
        } catch {
            throw (
                'Primary report-only restoration failed: ' +
                "$($primaryRestoreError.Exception.Message) " +
                'Fallback restoration also failed: ' +
                "$($_.Exception.Message)"
            )
        }
        throw (
            'Primary report-only restoration failed, but fallback restoration ' +
            "succeeded: $($primaryRestoreError.Exception.Message)"
        )
    }
}

function Get-LabPolicyRecoveryState {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$IsolationState,
        [Parameter(Mandatory)][string]$StatePath
    )

    $policyState = if ($IsolationState.Contains('labPolicy')) {
        $IsolationState['labPolicy']
    } elseif (Test-Path -LiteralPath $StatePath) {
        Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    } else {
        throw 'No recorded lab Conditional Access policy is available for recovery.'
    }
    if ($IsolationState['tenantId'] -ne $TenantId -or
        $policyState.applicationId -ne $IsolationState['applicationId'] -or
        [string]::IsNullOrWhiteSpace([string]$policyState.policyId) -or
        [string]::IsNullOrWhiteSpace([string]$policyState.policyDisplayName) -or
        [string]::IsNullOrWhiteSpace([string]$policyState.groupId) -or
        [string]::IsNullOrWhiteSpace(
            [string]$policyState.authenticationStrengthId
        )) {
        throw 'Recorded lab Conditional Access recovery state is incomplete.'
    }
    return $policyState
}

# Public Microsoft-managed Conditional Access policy template identity.
$expectedInterferingPolicyName = 'Multifactor authentication for Microsoft partners and vendors'
$expectedInterferingTemplateId = '4200930c-0da2-4e33-ca02-000000000004'

function Test-ExactStringSet {
    param(
        [AllowEmptyCollection()][object[]]$Actual,
        [AllowEmptyCollection()][object[]]$Expected
    )

    $actualValues = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    return (
        $actualValues.Count -eq $expectedValues.Count -and
        -not (Compare-Object `
            -ReferenceObject $expectedValues `
            -DifferenceObject $actualValues `
            -CaseSensitive)
    )
}

function Assert-ExactStringSet {
    param(
        [AllowEmptyCollection()][object[]]$Actual,
        [AllowEmptyCollection()][object[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-ExactStringSet -Actual $Actual -Expected $Expected)) {
        throw "Interfering policy '$Label' does not match its expected values."
    }
}

function Assert-InterferingMfaPolicy {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$PolicyId
    )

    if ($Policy.id -ne $PolicyId -or
        $Policy.displayName -cne $expectedInterferingPolicyName -or
        $Policy.state -ne 'enabled' -or
        $Policy.templateId -ne $expectedInterferingTemplateId -or
        $Policy.grantControls.operator -ne 'OR' -or
        $Policy.grantControls.authenticationStrength -or
        @($Policy.conditions.users.includeGroups).Count -ne 0 -or
        @($Policy.conditions.users.includeRoles).Count -ne 0) {
        throw "Policy '$PolicyId' is not the expected enabled Microsoft-managed MFA template."
    }
    Assert-ExactStringSet `
        -Actual @($Policy.conditions.users.includeUsers) `
        -Expected @('All') `
        -Label "$PolicyId user scope"
    Assert-ExactStringSet `
        -Actual @($Policy.conditions.applications.includeApplications) `
        -Expected @('All') `
        -Label "$PolicyId application scope"
    Assert-ExactStringSet `
        -Actual @($Policy.conditions.clientAppTypes) `
        -Expected @('all') `
        -Label "$PolicyId client app types"
    Assert-ExactStringSet `
        -Actual @($Policy.grantControls.builtInControls) `
        -Expected @('mfa') `
        -Label "$PolicyId grant controls"
}

function Get-GraphPolicy {
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [ValidateRange(10, 180)][int]$TimeoutSeconds = 120
    )

    $uri = (
        'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/' +
        $PolicyId
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $uri
        } catch {
            if ($_.Exception.Message -notmatch 'configured HttpClient.Timeout') {
                throw
            }
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
        }
    } while ((Get-Date) -lt $deadline)
    throw "Policy '$PolicyId' was not readable within $TimeoutSeconds seconds."
}

function ConvertTo-PolicyModifiedDateTime {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$PolicyId
    )

    try {
        if ($Value -is [DateTimeOffset]) {
            return [DateTimeOffset]$Value
        }
        if ($Value -is [DateTime]) {
            $dateTime = [DateTime]$Value
            if ($dateTime.Kind -eq [DateTimeKind]::Unspecified) {
                $dateTime = [DateTime]::SpecifyKind($dateTime, [DateTimeKind]::Utc)
            }
            return [DateTimeOffset]$dateTime
        }
        return [DateTimeOffset]::Parse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
    } catch {
        throw "Policy '$PolicyId' has no usable modifiedDateTime."
    }
}

function Get-PolicyInvariantSha256 {
    param(
        [Parameter(Mandatory)][object]$Policy
    )

    $copy = $Policy |
        ConvertTo-Json -Depth 30 |
        ConvertFrom-Json -AsHashtable
    [void]$copy.Remove('@odata.context')
    [void]$copy.Remove('modifiedDateTime')
    $copy['conditions']['applications']['excludeApplications'] = @()
    $canonical = ConvertTo-CanonicalValue -Value $copy
    $json = $canonical | ConvertTo-Json -Depth 30 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($sha256.ComputeHash($bytes)).ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function ConvertTo-CanonicalValue {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @(
            $Value.Keys |
                ForEach-Object { [string]$_ } |
                Sort-Object -CaseSensitive
        )) {
            $result[$key] = ConvertTo-CanonicalValue -Value $Value[$key]
        }
        return $result
    }
    if ($Value -is [pscustomobject]) {
        $result = [ordered]@{}
        foreach ($property in @(
            $Value.PSObject.Properties |
                Sort-Object Name -CaseSensitive
        )) {
            $result[$property.Name] = ConvertTo-CanonicalValue `
                -Value $property.Value
        }
        return $result
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $items.Add((ConvertTo-CanonicalValue -Value $item))
        }
        $sortedItems = @(
            $items |
                Sort-Object {
                    $_ | ConvertTo-Json -Depth 30 -Compress
                } -CaseSensitive
        )
        return ,$sortedItems
    }
    return $Value
}

function Wait-GraphPolicyExclusions {
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [AllowEmptyCollection()][object[]]$ExpectedExclusions,
        [Parameter(Mandatory)][string]$ExpectedInvariantSha256,
        [Parameter(Mandatory)][DateTimeOffset]$PreviousModifiedDateTime,
        [ValidateRange(10, 180)][int]$TimeoutSeconds = 120
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $policy = Get-GraphPolicy -PolicyId $PolicyId -TimeoutSeconds 30
        Assert-InterferingMfaPolicy -Policy $policy -PolicyId $PolicyId
        if (Test-ExactStringSet `
            -Actual @($policy.conditions.applications.excludeApplications) `
            -Expected $ExpectedExclusions) {
            $currentModifiedDateTime = ConvertTo-PolicyModifiedDateTime `
                -Value $policy.modifiedDateTime `
                -PolicyId $PolicyId
            if ($currentModifiedDateTime -le $PreviousModifiedDateTime) {
                if ((Get-Date) -lt $deadline) {
                    Start-Sleep -Seconds 5
                    continue
                }
                break
            }
            $actualInvariantSha256 = Get-PolicyInvariantSha256 -Policy $policy
            if ($actualInvariantSha256 -cne $ExpectedInvariantSha256) {
                throw (
                    "Policy '$PolicyId' changed outside excludeApplications " +
                    'during the isolation transaction.'
                )
            }
            return $policy
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
        }
    } while ((Get-Date) -lt $deadline)
    throw (
        "Policy '$PolicyId' exclusions and modifiedDateTime did not converge " +
        "within $TimeoutSeconds seconds."
    )
}

function Write-IsolationState {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$StateRecord
    )

    $operationId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$conditionalAccessIsolationStatePath.$operationId.tmp"
    $backupPath = "$conditionalAccessIsolationStatePath.$operationId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($StateRecord | ConvertTo-Json -Depth 12),
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $conditionalAccessIsolationStatePath) {
            [IO.File]::Replace(
                $temporaryPath,
                $conditionalAccessIsolationStatePath,
                $backupPath,
                $true
            )
        } else {
            [IO.File]::Move($temporaryPath, $conditionalAccessIsolationStatePath)
        }
    } finally {
        foreach ($cleanupPath in @($temporaryPath, $backupPath)) {
            if (Test-Path -LiteralPath $cleanupPath) {
                Remove-Item -LiteralPath $cleanupPath -Force
            }
        }
    }
}

function New-IsolationBaseline {
    param(
        [Parameter(Mandatory)][string[]]$PolicyIds,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][object]$LabPolicyState,
        [Parameter(Mandatory)][string]$ProofSetId
    )

    $policies = @(
        foreach ($policyId in $PolicyIds) {
            $policy = Get-GraphPolicy -PolicyId $policyId
            Assert-InterferingMfaPolicy -Policy $policy -PolicyId $policyId
            $modifiedDateTime = ConvertTo-PolicyModifiedDateTime `
                -Value $policy.modifiedDateTime `
                -PolicyId $policyId
            if ($ApplicationId -in @(
                $policy.conditions.applications.excludeApplications
            )) {
                throw (
                    "Policy '$policyId' already excludes lab application " +
                    "'$ApplicationId'; refusing to overwrite an untracked baseline."
                )
            }
            [ordered]@{
                displayName = $policy.displayName
                excludeApplications = @(
                    $policy.conditions.applications.excludeApplications
                )
                id = $policy.id
                includeApplications = @(
                    $policy.conditions.applications.includeApplications
                )
                invariantSha256 = Get-PolicyInvariantSha256 -Policy $policy
                modifiedDateTime = $modifiedDateTime.ToString('o')
                templateId = $policy.templateId
            }
        }
    )
    return [ordered]@{
        applicationId = $ApplicationId
        appliedPolicyIds = @()
        createdAt = (Get-Date).ToString('o')
        labPolicy = [ordered]@{
            applicationId = $LabPolicyState.applicationId
            authenticationStrengthId = $LabPolicyState.authenticationStrengthId
            groupId = $LabPolicyState.groupId
            policyDisplayName = $LabPolicyState.policyDisplayName
            policyId = $LabPolicyState.policyId
        }
        mutationRequestedPolicyIds = @()
        policies = $policies
        proofSetId = $ProofSetId
        restoredPolicyIds = @()
        schemaVersion = 3
        status = 'prepared'
        tenantId = $TenantId
    }
}

function Set-LabApplicationExclusions {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Baseline
    )

    $Baseline['status'] = 'applying'
    $Baseline['applyingAt'] = (Get-Date).ToString('o')
    Write-IsolationState -StateRecord $Baseline
    foreach ($record in @($Baseline.policies)) {
        $policy = Get-GraphPolicy -PolicyId $record.id
        Assert-InterferingMfaPolicy -Policy $policy -PolicyId $record.id
        Assert-ExactStringSet `
            -Actual @($policy.conditions.applications.excludeApplications) `
            -Expected @($record.excludeApplications) `
            -Label "$($record.id) original exclusions"
        if ((Get-PolicyInvariantSha256 -Policy $policy) -cne
            $record.invariantSha256) {
            throw "Policy '$($record.id)' changed after its isolation snapshot."
        }
        $newExclusions = @(
            @($record.excludeApplications) + @($Baseline.applicationId) |
                Sort-Object -Unique
        )
        $Baseline['mutationRequestedPolicyIds'] = @(
            @($Baseline.mutationRequestedPolicyIds) + @($record.id) |
                Sort-Object -Unique
        )
        Write-IsolationState -StateRecord $Baseline
        $body = @{
            conditions = @{
                applications = @{
                    excludeApplications = $newExclusions
                }
            }
        }
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri (
                'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/' +
                $record.id
            ) `
            -Body ($body | ConvertTo-Json -Depth 8) `
            -ContentType 'application/json' | Out-Null
        Wait-GraphPolicyExclusions `
            -PolicyId $record.id `
            -ExpectedExclusions $newExclusions `
            -ExpectedInvariantSha256 $record.invariantSha256 `
            -PreviousModifiedDateTime (
                ConvertTo-PolicyModifiedDateTime `
                    -Value $policy.modifiedDateTime `
                    -PolicyId $record.id
            ) | Out-Null
        $Baseline['appliedPolicyIds'] = @(
            @($Baseline.appliedPolicyIds) + @($record.id) |
                Sort-Object -Unique
        )
        Write-IsolationState -StateRecord $Baseline
    }
    $Baseline['status'] = 'applied'
    $Baseline['appliedAt'] = (Get-Date).ToString('o')
    Write-IsolationState -StateRecord $Baseline
}

function Restore-LabApplicationExclusions {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Baseline
    )

    $policyRestoreErrors = [Collections.Generic.List[string]]::new()
    $journalErrors = [Collections.Generic.List[string]]::new()
    $Baseline['status'] = 'restoring'
    $Baseline['restoringAt'] = (Get-Date).ToString('o')
    try {
        Write-IsolationState -StateRecord $Baseline
    } catch {
        $journalErrors.Add("restoring transition: $($_.Exception.Message)")
    }
    foreach ($record in @($Baseline.policies)) {
        try {
            $policy = Get-GraphPolicy -PolicyId $record.id
            Assert-InterferingMfaPolicy -Policy $policy -PolicyId $record.id
            if ((Get-PolicyInvariantSha256 -Policy $policy) -cne
                $record.invariantSha256) {
                throw (
                    "Policy '$($record.id)' changed outside excludeApplications; " +
                    'automatic exact restoration is unsafe.'
                )
            }
            $baselineExclusions = @($record.excludeApplications)
            $temporaryExclusions = @(
                $baselineExclusions + @($Baseline.applicationId) |
                    Sort-Object -Unique
            )
            $currentExclusions = @(
                $policy.conditions.applications.excludeApplications
            )
            $isBaseline = Test-ExactStringSet `
                -Actual $currentExclusions `
                -Expected $baselineExclusions
            $isTemporary = Test-ExactStringSet `
                -Actual $currentExclusions `
                -Expected $temporaryExclusions
            if (-not $isBaseline -and -not $isTemporary) {
                throw (
                    "Policy '$($record.id)' exclusions changed concurrently; " +
                    'preserving the current values for manual recovery.'
                )
            }

            $mutationWasRequested = (
                $record.id -in @($Baseline.mutationRequestedPolicyIds)
            )
            if ($isTemporary -or $mutationWasRequested) {
                $body = @{
                    conditions = @{
                        applications = @{
                            excludeApplications = $baselineExclusions
                        }
                    }
                }
                Invoke-MgGraphRequest `
                    -Method PATCH `
                    -Uri (
                        'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/' +
                        $record.id
                    ) `
                    -Body ($body | ConvertTo-Json -Depth 8) `
                    -ContentType 'application/json' | Out-Null
                Wait-GraphPolicyExclusions `
                    -PolicyId $record.id `
                    -ExpectedExclusions $baselineExclusions `
                    -ExpectedInvariantSha256 $record.invariantSha256 `
                    -PreviousModifiedDateTime (
                        ConvertTo-PolicyModifiedDateTime `
                            -Value $policy.modifiedDateTime `
                            -PolicyId $record.id
                    ) | Out-Null
            }
            $Baseline['restoredPolicyIds'] = @(
                @($Baseline.restoredPolicyIds) + @($record.id) |
                    Sort-Object -Unique
            )
        } catch {
            $policyRestoreErrors.Add("$($record.id): $($_.Exception.Message)")
            continue
        }
        try {
            Write-IsolationState -StateRecord $Baseline
        } catch {
            $journalErrors.Add("$($record.id) checkpoint: $($_.Exception.Message)")
        }
    }
    if ($policyRestoreErrors.Count -eq 0) {
        $Baseline['status'] = 'restored'
        $Baseline['restoredAt'] = (Get-Date).ToString('o')
        try {
            Write-IsolationState -StateRecord $Baseline
        } catch {
            $journalErrors.Add("restored transition: $($_.Exception.Message)")
        }
    }
    $allErrors = @(
        $policyRestoreErrors | ForEach-Object { "policy: $_" }
        $journalErrors | ForEach-Object { "journal: $_" }
    )
    if ($allErrors.Count -ne 0) {
        throw "Interfering policy restoration failed: $($allErrors -join ' | ')"
    }
}

function Assert-LabApplicationExclusionsRestored {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Baseline
    )

    foreach ($record in @($Baseline.policies)) {
        $policy = Get-GraphPolicy -PolicyId $record.id
        Assert-InterferingMfaPolicy -Policy $policy -PolicyId $record.id
        Assert-ExactStringSet `
            -Actual @($policy.conditions.applications.excludeApplications) `
            -Expected @($record.excludeApplications) `
            -Label "$($record.id) restored exclusions"
        if ((Get-PolicyInvariantSha256 -Policy $policy) -cne
            $record.invariantSha256) {
            throw (
                "Policy '$($record.id)' differs from its isolation baseline " +
                'outside excludeApplications.'
            )
        }
    }
}

$configurePolicy = Join-Path $PSScriptRoot 'Configure-ConditionalAccess.ps1'
$invokeLocal = Join-Path $PSScriptRoot 'Invoke-LocalFeasibility.ps1'
$completeEvidence = Join-Path $PSScriptRoot 'Complete-CbaSignInEvidence.ps1'
$labRoot = Split-Path -Parent $PSScriptRoot
$conditionalAccessStatePath = Join-Path $labRoot '.lab-state\conditional-access.json'
$conditionalAccessIsolationStatePath = Join-Path `
    $labRoot `
    '.lab-state\conditional-access-isolation.json'
$conditionalAccessIsolationLockPath = Join-Path `
    $labRoot `
    '.lab-state\conditional-access-isolation.lock'
$githubStatePath = Join-Path $labRoot '.lab-state\github.json'
$runnerStatePath = Join-Path $labRoot '.lab-state\runner.json'
. (Join-Path $PSScriptRoot 'Proof-Set.ps1')

function Get-ValidatedCloudProofSet {
    foreach ($requiredPath in @($githubStatePath, $runnerStatePath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required cloud proof state '$requiredPath' does not exist."
        }
    }
    $githubState = Get-Content -LiteralPath $githubStatePath -Raw |
        ConvertFrom-Json
    $runnerState = Get-Content -LiteralPath $runnerStatePath -Raw |
        ConvertFrom-Json
    if ($runnerState.repository -cne $githubState.repository -or
        $runnerState.workflowFinalStatus -ne 'completed' -or
        $runnerState.workflowFinalConclusion -ne 'success' -or
        $runnerState.aciContainerDeleted -ne $true -or
        $runnerState.githubRunnerDeregistered -ne $true -or
        $runnerState.identityReceiptSha256 -notmatch '^[a-f0-9]{64}$' -or
        $runnerState.networkReceiptSha256 -notmatch '^[a-f0-9]{64}$') {
        throw 'The cloud runner proof is incomplete or cleanup is not verified.'
    }
    $localHeadSha = (& git -C $labRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or
        $localHeadSha -cne $runnerState.workflowHeadSha) {
        throw (
            "Local HEAD '$localHeadSha' does not match cloud-tested revision " +
            "'$($runnerState.workflowHeadSha)'."
        )
    }
    $trackedChanges = @(
        & git -C $labRoot status --porcelain --untracked-files=no
    )
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count -ne 0) {
        throw 'Conditional Access proof requires a clean cloud-tested checkout.'
    }
    $calculatedProofSetId = Get-E2eProofSetId `
        -Repository $runnerState.repository `
        -RunId ([long]$runnerState.workflowRunId) `
        -HeadSha $runnerState.workflowHeadSha `
        -WorkflowFile $runnerState.workflowFile `
        -OidcSubject $githubState.subject
    if ($runnerState.proofSetId -cne $calculatedProofSetId) {
        throw 'The cloud runner proof-set identifier failed exact recomputation.'
    }
    return $calculatedProofSetId
}

$policyManaged = $false
$managedPolicy = $null
$isolationBaseline = $null
$interferingPoliciesManaged = $false
$isolationLockStream = $null
$proofSetId = $null
$interferingPolicyIds = @(
    if ($InterferingPolicyIdsCsv) {
        $InterferingPolicyIdsCsv.Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    }
)
if ($interferingPolicyIds.Count -eq 0) {
    throw 'At least one explicit interfering policy ID is required.'
}
if (-not $ConfirmExclusiveConditionalAccessWindow) {
    throw (
        'ConfirmExclusiveConditionalAccessWindow is required because Microsoft ' +
        'Graph Conditional Access PATCH does not support an ETag precondition.'
    )
}
foreach ($policyId in $interferingPolicyIds) {
    $parsedPolicyId = [guid]::Empty
    if (-not [guid]::TryParseExact(
        [string]$policyId,
        'D',
        [ref]$parsedPolicyId
    )) {
        throw "Interfering policy ID '$policyId' is not a GUID."
    }
}

try {
    try {
        $isolationLockStream = [IO.File]::Open(
            $conditionalAccessIsolationLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch [IO.IOException] {
        throw 'Another Conditional Access isolation transaction is already running.'
    }
    $lockRecord = [ordered]@{
        processId = $PID
        startedAt = (Get-Date).ToString('o')
        tenantId = $TenantId
    } | ConvertTo-Json -Compress
    $lockBytes = [Text.Encoding]::UTF8.GetBytes($lockRecord)
    $isolationLockStream.SetLength(0)
    $isolationLockStream.Write($lockBytes, 0, $lockBytes.Length)
    $isolationLockStream.Flush($true)

    $graphTokenExpiresAt = Connect-ValidatedGraphDeviceCode
    $requiredTokenSeconds = if ($RestoreIsolationOnly) {
        600
    } else {
        $PropagationSeconds +
            $NegativeFinalizationSeconds +
            ($EvidenceTimeoutMinutes * 60) +
            600
    }
    $requiredUntil = [DateTimeOffset]::UtcNow.AddSeconds($requiredTokenSeconds)
    if ($requiredUntil -ge $graphTokenExpiresAt) {
        throw (
            'The requested proof window exceeds the non-refreshable Graph token ' +
            "lifetime. Token expires at '$($graphTokenExpiresAt.ToString('o'))'; " +
            "the bounded run requires authorization through '$($requiredUntil.ToString('o'))'."
        )
    }
    Write-Host (
        "GRAPH_TOKEN_WINDOW_VERIFIED expires=$($graphTokenExpiresAt.ToString('o')) " +
        "requiredThrough=$($requiredUntil.ToString('o'))"
    )

    $proofError = $null
    $labRestoreError = $null
    $globalRestoreError = $null
    try {
        $priorIsolation = $null
        if (Test-Path -LiteralPath $conditionalAccessIsolationStatePath) {
            $priorIsolation = Get-Content `
                -LiteralPath $conditionalAccessIsolationStatePath `
                -Raw | ConvertFrom-Json -AsHashtable
            Assert-ExactStringSet `
                -Actual @($priorIsolation['policies'].id) `
                -Expected $interferingPolicyIds `
                -Label 'recovery policy IDs'
            if ($priorIsolation['tenantId'] -ne $TenantId -or
                [string]::IsNullOrWhiteSpace(
                    [string]$priorIsolation['applicationId']
                )) {
                throw 'Isolation recovery state does not match this tenant.'
            }
            if ($priorIsolation['schemaVersion'] -ne 3) {
                throw 'Isolation state schema is unsupported; manual review is required.'
            }
            if ($priorIsolation['status'] -ne 'restored') {
                $recoveryErrors = [Collections.Generic.List[string]]::new()
                $recoveryPolicyState = Get-LabPolicyRecoveryState `
                    -IsolationState $priorIsolation `
                    -StatePath $conditionalAccessStatePath
                try {
                    Write-Host 'CA_PHASE=RECOVER_REPORT_ONLY'
                    Restore-LabPolicyReportOnly `
                        -PolicyState $recoveryPolicyState `
                        -ConfigureScript $configurePolicy
                } catch {
                    $recoveryErrors.Add(
                        "Lab policy restoration: $($_.Exception.Message)"
                    )
                }
                try {
                    Write-Host 'CA_PHASE=RECOVER_GLOBAL_POLICY_EXCLUSIONS'
                    Restore-LabApplicationExclusions -Baseline $priorIsolation
                    Write-Host 'CA_PHASE=GLOBAL_POLICY_EXCLUSIONS_RECOVERED'
                } catch {
                    $recoveryErrors.Add(
                        "Managed policy restoration: $($_.Exception.Message)"
                    )
                }
                if ($recoveryErrors.Count -ne 0) {
                    throw "Isolation recovery failed: $($recoveryErrors -join ' | ')"
                }
            }
        }
        if ($RestoreIsolationOnly) {
            if (-not $priorIsolation) {
                throw "No isolation state exists at '$conditionalAccessIsolationStatePath'."
            }
            $recoveryPolicyState = Get-LabPolicyRecoveryState `
                -IsolationState $priorIsolation `
                -StatePath $conditionalAccessStatePath
            $verificationErrors = [Collections.Generic.List[string]]::new()
            try {
                Write-Host 'CA_PHASE=VERIFY_REPORT_ONLY'
                Restore-LabPolicyReportOnly `
                    -PolicyState $recoveryPolicyState `
                    -ConfigureScript $configurePolicy
            } catch {
                $verificationErrors.Add(
                    "Lab policy verification: $($_.Exception.Message)"
                )
            }
            try {
                Assert-LabApplicationExclusionsRestored `
                    -Baseline $priorIsolation
            } catch {
                $verificationErrors.Add(
                    "Managed policy verification: $($_.Exception.Message)"
                )
            }
            if ($verificationErrors.Count -ne 0) {
                throw (
                    'Isolation recovery verification failed: ' +
                    ($verificationErrors -join ' | ')
                )
            }
            Write-Host 'CA_ISOLATION_RECOVERY_VERIFIED'
            return
        }

        $proofSetId = Get-ValidatedCloudProofSet
        Write-Host "CA_PROOF_SET_VERIFIED id=$proofSetId"

        $applicationStatePath = Join-Path $labRoot '.lab-state\application.json'
        if (-not (Test-Path -LiteralPath $applicationStatePath)) {
            throw "Required application state '$applicationStatePath' does not exist."
        }
        $application = Get-Content `
            -LiteralPath $applicationStatePath `
            -Raw | ConvertFrom-Json
        if ($application.tenantId -ne $TenantId -or
            [string]::IsNullOrWhiteSpace([string]$application.appId)) {
            throw 'Local application state does not match the target tenant.'
        }

        Write-Host 'CA_PHASE=REPORT_ONLY_PRECHECK'
        & $configurePolicy `
            -TenantId $TenantId `
            -State enabledForReportingButNotEnforced
        $managedPolicy = Get-Content `
            -LiteralPath $conditionalAccessStatePath `
            -Raw | ConvertFrom-Json
        if ($managedPolicy.tenantId -ne $TenantId -or
            $managedPolicy.applicationId -ne $application.appId -or
            $managedPolicy.policyState -ne
                'enabledForReportingButNotEnforced') {
            throw 'The report-only precheck did not record the exact managed policy.'
        }
        $policyManaged = $true

        $isolationBaseline = New-IsolationBaseline `
            -PolicyIds $interferingPolicyIds `
            -ApplicationId $application.appId `
            -LabPolicyState $managedPolicy `
            -ProofSetId $proofSetId
        Write-IsolationState -StateRecord $isolationBaseline
        $interferingPoliciesManaged = $true
        Write-Host 'CA_PHASE=APPLY_LAB_APP_EXCLUSIONS'
        Set-LabApplicationExclusions -Baseline $isolationBaseline
        Write-Host 'CA_PHASE=LAB_APP_EXCLUSIONS_VERIFIED'

        try {
            Write-Host 'CA_PHASE=ENABLE_AND_READBACK'
            & $configurePolicy -TenantId $TenantId -State enabled

            Write-Host "CA_PHASE=PROPAGATION_WAIT seconds=$PropagationSeconds"
            Start-Sleep -Seconds $PropagationSeconds

            if ($BrowserScenario -eq 'Both') {
                Write-Host 'CA_PHASE=MFA_POSITIVE_BROWSER_START'
                & $invokeLocal `
                    -AuthenticationStrengthPositive `
                    -DeferSignInEvidence `
                    -ProofSetId $proofSetId
                Write-Host 'CA_PHASE=MFA_POSITIVE_BROWSER_VERIFIED'
            }

            Write-Host 'CA_PHASE=SFA_NEGATIVE_BROWSER_START'
            & $invokeLocal `
                -AuthenticationStrengthNegative `
                -DeferSignInEvidence `
                -ProofSetId $proofSetId
            Write-Host 'CA_PHASE=SFA_NEGATIVE_BROWSER_VERIFIED'
            Write-Host (
                'CA_PHASE=NEGATIVE_FINALIZATION_WAIT ' +
                "seconds=$NegativeFinalizationSeconds"
            )
            Start-Sleep -Seconds $NegativeFinalizationSeconds
        } finally {
            if ($policyManaged) {
                Write-Host 'CA_PHASE=RESTORE_REPORT_ONLY'
                try {
                    Restore-LabPolicyReportOnly `
                        -PolicyState $managedPolicy `
                        -ConfigureScript $configurePolicy
                } catch {
                    $labRestoreError = $_
                }
            }
        }
    } catch {
        $proofError = $_
    } finally {
        if ($interferingPoliciesManaged) {
            Write-Host 'CA_PHASE=RESTORE_GLOBAL_POLICY_EXCLUSIONS'
            try {
                Restore-LabApplicationExclusions -Baseline $isolationBaseline
                Write-Host 'CA_PHASE=GLOBAL_POLICY_EXCLUSIONS_RESTORED'
            } catch {
                $globalRestoreError = $_
            }
        }
    }

    $transactionErrors = [Collections.Generic.List[string]]::new()
    if ($proofError) {
        $transactionErrors.Add("Proof execution: $($proofError.Exception.Message)")
    }
    if ($labRestoreError) {
        $transactionErrors.Add(
            "Lab policy restoration: $($labRestoreError.Exception.Message)"
        )
    }
    if ($globalRestoreError) {
        $transactionErrors.Add(
            "Managed policy restoration: $($globalRestoreError.Exception.Message)"
        )
    }
    if ($transactionErrors.Count -ne 0) {
        throw "Conditional Access proof failed: $($transactionErrors -join ' | ')"
    }

    Write-Host 'CA_PHASE=HISTORICAL_EVIDENCE_START'
    $evidenceScenarios = if ($BrowserScenario -eq 'Negative') {
        @('negative')
    } else {
        @('positive', 'negative')
    }
    & $completeEvidence `
        -Scenarios $evidenceScenarios `
        -TimeoutMinutes $EvidenceTimeoutMinutes
    Write-Host 'CA_END_TO_END_VERIFIED'
} finally {
    try {
        Disconnect-MgGraph -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Graph disconnect failed: $($_.Exception.Message)"
    } finally {
        if ($isolationLockStream) {
            try {
                $isolationLockStream.Dispose()
            } catch {
                Write-Warning "Isolation lock release failed: $($_.Exception.Message)"
            }
            try {
                Remove-Item -LiteralPath $conditionalAccessIsolationLockPath -Force
            } catch {
                Write-Warning (
                    "Isolation lock was released but " +
                    "'$conditionalAccessIsolationLockPath' could not be deleted: " +
                    $_.Exception.Message
                )
            }
        }
    }
}
