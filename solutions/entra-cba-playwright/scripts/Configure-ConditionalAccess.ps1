[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [string]$PolicyDisplayName = 'CA - Entra CBA Playwright POC - Phishing-resistant MFA',
    [ValidateSet('disabled', 'enabledForReportingButNotEnforced', 'enabled')]
    [string]$State = 'enabledForReportingButNotEnforced',
    [switch]$Connect
)

$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$applicationStatePath = Join-Path $stateDirectory 'application.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$conditionalAccessOperationPath = Join-Path `
    $stateDirectory `
    'conditional-access-operation.json'
$conditionalAccessOperationLockPath = Join-Path `
    $stateDirectory `
    'conditional-access-operation.lock'
try {
    $conditionalAccessOperationLock = [IO.File]::Open(
        $conditionalAccessOperationLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another Conditional Access configuration owns the exclusive local lock.'
}
try {

foreach ($requiredPath in @($applicationStatePath, $entraStatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required state file '$requiredPath' does not exist."
    }
}

$application = Get-Content -LiteralPath $applicationStatePath -Raw | ConvertFrom-Json
$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
$conditionalAccessStateRecord = if (Test-Path -LiteralPath $conditionalAccessStatePath) {
    Get-Content -LiteralPath $conditionalAccessStatePath -Raw | ConvertFrom-Json
} else {
    $null
}
$provisionalConditionalAccessState = if (
    $conditionalAccessStateRecord -and
    $conditionalAccessStateRecord.policyState -ceq 'creationPendingReadback'
) {
    $conditionalAccessStateRecord
}
else {
    $null
}
$existingConditionalAccessState = if ($provisionalConditionalAccessState) {
    $null
}
else {
    $conditionalAccessStateRecord
}
if (
    $provisionalConditionalAccessState -and
    -not (Test-Path -LiteralPath $conditionalAccessOperationPath -PathType Leaf)
) {
    throw 'Provisional Conditional Access state is missing its creation journal.'
}
if ($application.tenantId -ne $TenantId -or $entra.tenantId -ne $TenantId) {
    throw 'Local application or Entra state belongs to a different tenant.'
}

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force

$requiredScopes = @(
    'Application.Read.All',
    'Policy.ReadWrite.ConditionalAccess'
)
$context = Get-MgContext
$missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
$hasRequiredContext = (
    $context -and
    $context.TenantId -eq $TenantId -and
    $missingScopes.Count -eq 0
)

if (-not $hasRequiredContext) {
    if (-not $Connect) {
        throw "No reusable Microsoft Graph context for tenant '$TenantId' has scopes: $($requiredScopes -join ', '). Rerun with -Connect to authorize once in the system browser."
    }

    Connect-MgGraph `
        -TenantId $TenantId `
        -Scopes $requiredScopes `
        -ContextScope CurrentUser `
        -ClientTimeout 600 `
        -NoWelcome
    $context = Get-MgContext
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
}

if (-not $context -or $context.TenantId -ne $TenantId -or $missingScopes.Count -ne 0) {
    throw "Microsoft Graph authorization for '$($requiredScopes -join ', ')' in tenant '$TenantId' is required."
}

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)][ValidateSet('POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Body
    )

    Invoke-MgGraphRequest `
        -Method $Method `
        -Uri $Uri `
        -Body ($Body | ConvertTo-Json -Depth 20) `
        -ContentType 'application/json'
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)

    $items = [Collections.Generic.List[object]]::new()
    while ($Uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri
        foreach ($item in @($response.value)) {
            $items.Add($item)
        }
        $Uri = if ($response -is [Collections.IDictionary]) {
            if ($response.Contains('@odata.nextLink')) {
                [string]$response['@odata.nextLink']
            } else {
                $null
            }
        } else {
            $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
            if ($null -ne $nextLinkProperty) {
                [string]$nextLinkProperty.Value
            } else {
                $null
            }
        }
    }
    return $items.ToArray()
}

function Get-ReconciledGraphMatches {
    param(
        [Parameter(Mandatory)][scriptblock]$Lookup,
        [switch]$WaitForAppearance
    )

    $appearanceDeadline = (Get-Date).AddMinutes(10)
    $absenceDeadline = $appearanceDeadline.AddSeconds(30)
    $consecutiveAbsenceChecks = 0
    do {
        $matches = @(& $Lookup)
        if ($matches.Count -ne 0 -or -not $WaitForAppearance) {
            return $matches
        }
        if ((Get-Date) -ge $appearanceDeadline) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return @()
            }
        }
        Start-Sleep -Seconds 10
    } while ((Get-Date) -lt $absenceDeadline)
    throw 'Conditional Access policy absence could not be proven after the appearance window.'
}

function Get-ConditionalAccessPolicy {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [AllowNull()][string]$ExpectedState,
        [ValidateRange(5, 120)][int]$TimeoutSeconds = 60
    )

    $requestContext = Get-MgRequestContext
    $originalClientTimeout = [int][Math]::Ceiling(
        $requestContext.ClientTimeout.TotalSeconds
    )
    $originalMaxRetry = [int]$requestContext.MaxRetry
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Set-MgRequestContext -MaxRetry 0 -Confirm:$false | Out-Null

    try {
        do {
            $remainingSeconds = [int][Math]::Ceiling(
                ($deadline - (Get-Date)).TotalSeconds
            )
            if ($remainingSeconds -le 0) {
                break
            }
            Set-MgRequestContext `
                -ClientTimeout ([Math]::Min(10, $remainingSeconds)) `
                -Confirm:$false | Out-Null

            try {
                $policy = Invoke-MgGraphRequest -Method GET -Uri $Uri
                if (-not $ExpectedState -or $policy.state -eq $ExpectedState) {
                    return $policy
                }
            } catch {
                $responseProperty = $_.Exception.PSObject.Properties['Response']
                $statusCode = 0
                if ($null -ne $responseProperty -and $null -ne $responseProperty.Value) {
                    $statusCodeProperty = $responseProperty.Value.PSObject.Properties['StatusCode']
                    if ($null -ne $statusCodeProperty) {
                        $statusCode = [int]$statusCodeProperty.Value
                    }
                }
                $errorDetailsMessage = if ($null -ne $_.ErrorDetails) {
                    [string]$_.ErrorDetails.Message
                } else {
                    ''
                }
                $isResourceNotFound = (
                    $statusCode -eq 404 -and
                    $errorDetailsMessage -match '"code":"ResourceNotFound"'
                )
                $isRequestTimeout = (
                    $_.Exception.Message -match 'configured HttpClient.Timeout'
                )
                if (-not $isResourceNotFound -and -not $isRequestTimeout) {
                    throw
                }
            }

            $remainingSeconds = [int][Math]::Floor(
                ($deadline - (Get-Date)).TotalSeconds
            )
            if ($remainingSeconds -gt 0) {
                Start-Sleep -Seconds ([Math]::Min(5, $remainingSeconds))
            }
        } while ((Get-Date) -lt $deadline)
    } finally {
        Set-MgRequestContext `
            -ClientTimeout $originalClientTimeout `
            -MaxRetry $originalMaxRetry `
            -Confirm:$false | Out-Null
    }

    $expectation = if ($ExpectedState) {
        " in state '$ExpectedState'"
    } else {
        ''
    }
    throw "Conditional Access policy was not readable$expectation within $TimeoutSeconds seconds."
}

function Write-ConditionalAccessState {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$StateRecord,
        [string]$Path = $conditionalAccessStatePath
    )

    $operationId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$Path.$operationId.tmp"
    $backupPath = "$Path.$operationId.bak"
    try {
        $json = $StateRecord | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText(
            $temporaryPath,
            $json,
            [Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $Path) {
            [IO.File]::Replace(
                $temporaryPath,
                $Path,
                $backupPath,
                $true
            )
        } else {
            [IO.File]::Move($temporaryPath, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        if (Test-Path -LiteralPath $backupPath) {
            Remove-Item -LiteralPath $backupPath -Force
        }
    }
}

function New-ConditionalAccessStateRecord {
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][bool]$PolicyCreated,
        [AllowNull()][string]$PolicyOriginalState,
        [Parameter(Mandatory)][string]$PolicyState
    )

    return [ordered]@{
        applicationId = $application.appId
        authenticationStrengthDisplayName = $strength.displayName
        authenticationStrengthId = $strength.id
        groupId = $entra.groupId
        policyCreated = $PolicyCreated
        policyDisplayName = $effectivePolicyDisplayName
        policyId = $PolicyId
        policyOriginalState = $PolicyOriginalState
        policyState = $PolicyState
        requestedPolicyDisplayName = $PolicyDisplayName
        schemaVersion = 2
        tenantId = $TenantId
        verifiedAt = (Get-Date).ToString('o')
    }
}

function Assert-ExactValues {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Actual,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Expected,
        [Parameter(Mandatory)][string]$Label
    )

    $actualValues = @($Actual | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $expectedValues = @($Expected | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ($actualValues.Count -ne $expectedValues.Count -or
        (Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues)) {
        throw "Conditional Access policy '$Label' does not match the isolated lab scope."
    }
}

function Test-IsNullOrEmpty {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) {
        return $true
    }
    if ($Value -is [string]) {
        return [string]::IsNullOrEmpty($Value)
    }
    if ($Value -is [Collections.IEnumerable]) {
        return @($Value).Count -eq 0
    }
    return $false
}

function Assert-NoUnexpectedProperties {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$AllowedProperties,
        [Parameter(Mandatory)][string]$Label
    )

    $properties = if ($Object -is [Collections.IDictionary]) {
        @($Object.Keys | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_
                Value = $Object[$_]
            }
        })
    } else {
        @($Object.PSObject.Properties)
    }

    foreach ($property in $properties) {
        if ($property.Name -notin $AllowedProperties -and
            -not (Test-IsNullOrEmpty -Value $property.Value)) {
            throw "Conditional Access $Label contains unexpected property '$($property.Name)'."
        }
    }
}

function Assert-LabPolicy {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$AuthenticationStrengthId
    )

    Assert-ExactValues `
        -Actual @($Policy.conditions.users.includeGroups) `
        -Expected @($GroupId) `
        -Label 'included groups'
    Assert-ExactValues `
        -Actual @($Policy.conditions.users.includeUsers) `
        -Expected @() `
        -Label 'included users'
    Assert-ExactValues `
        -Actual @($Policy.conditions.users.includeRoles) `
        -Expected @() `
        -Label 'included roles'
    Assert-ExactValues `
        -Actual @($Policy.conditions.users.excludeGroups) `
        -Expected @() `
        -Label 'excluded groups'
    Assert-ExactValues `
        -Actual @($Policy.conditions.users.excludeUsers) `
        -Expected @() `
        -Label 'excluded users'
    Assert-ExactValues `
        -Actual @($Policy.conditions.users.excludeRoles) `
        -Expected @() `
        -Label 'excluded roles'
    Assert-ExactValues `
        -Actual @($Policy.conditions.applications.includeApplications) `
        -Expected @($ApplicationId) `
        -Label 'included applications'
    Assert-ExactValues `
        -Actual @($Policy.conditions.applications.excludeApplications) `
        -Expected @() `
        -Label 'excluded applications'
    Assert-ExactValues `
        -Actual @($Policy.conditions.clientAppTypes) `
        -Expected @('all') `
        -Label 'client application types'

    Assert-ExactValues `
        -Actual @($Policy.conditions.applications.includeUserActions) `
        -Expected @() `
        -Label 'included user actions'
    Assert-ExactValues `
        -Actual @($Policy.conditions.applications.includeAuthenticationContextClassReferences) `
        -Expected @() `
        -Label 'included authentication contexts'
    Assert-ExactValues `
        -Actual @($Policy.grantControls.customAuthenticationFactors) `
        -Expected @() `
        -Label 'custom authentication factors'
    Assert-ExactValues `
        -Actual @($Policy.grantControls.termsOfUse) `
        -Expected @() `
        -Label 'terms of use'

    foreach ($conditionProperty in @(
        'platforms',
        'locations',
        'devices',
        'clientApplications',
        'authenticationFlows'
    )) {
        if (-not (Test-IsNullOrEmpty -Value $Policy.conditions.$conditionProperty)) {
            throw "Conditional Access policy contains unexpected '$conditionProperty' conditions."
        }
    }
    foreach ($guestProperty in @('includeGuestsOrExternalUsers', 'excludeGuestsOrExternalUsers')) {
        if (-not (Test-IsNullOrEmpty -Value $Policy.conditions.users.$guestProperty)) {
            throw "Conditional Access policy contains unexpected '$guestProperty' scope."
        }
    }
    if (-not (Test-IsNullOrEmpty -Value $Policy.conditions.applications.applicationFilter)) {
        throw 'Conditional Access policy contains an unexpected application filter.'
    }
    if (-not (Test-IsNullOrEmpty -Value $Policy.sessionControls)) {
        throw 'Conditional Access policy contains unexpected session controls.'
    }

    foreach ($riskProperty in @('signInRiskLevels', 'userRiskLevels', 'servicePrincipalRiskLevels')) {
        if (@($Policy.conditions.$riskProperty).Count -ne 0) {
            throw "Conditional Access policy contains unexpected '$riskProperty' values."
        }
    }

    if ($Policy.grantControls.operator -ne 'OR' -or
        $Policy.grantControls.authenticationStrength.id -ne $AuthenticationStrengthId -or
        @($Policy.grantControls.builtInControls).Count -ne 0) {
        throw 'Conditional Access grant controls do not exclusively require the expected authentication strength.'
    }

    Assert-NoUnexpectedProperties `
        -Object $Policy.conditions `
        -AllowedProperties @(
            '@odata.type',
            'applications',
            'authenticationFlows',
            'clientApplications',
            'clientAppTypes',
            'devices',
            'locations',
            'platforms',
            'servicePrincipalRiskLevels',
            'signInRiskLevels',
            'userRiskLevels',
            'users'
        ) `
        -Label 'conditions'
    Assert-NoUnexpectedProperties `
        -Object $Policy.conditions.users `
        -AllowedProperties @(
            '@odata.type',
            'excludeGroups',
            'excludeGuestsOrExternalUsers',
            'excludeRoles',
            'excludeUsers',
            'includeGroups',
            'includeGuestsOrExternalUsers',
            'includeRoles',
            'includeUsers'
        ) `
        -Label 'user scope'
    Assert-NoUnexpectedProperties `
        -Object $Policy.conditions.applications `
        -AllowedProperties @(
            '@odata.type',
            'applicationFilter',
            'excludeApplications',
            'includeApplications',
            'includeAuthenticationContextClassReferences',
            'includeUserActions'
        ) `
        -Label 'application scope'
    Assert-NoUnexpectedProperties `
        -Object $Policy.grantControls `
        -AllowedProperties @(
            '@odata.type',
            'authenticationStrength',
            'authenticationStrength@odata.context',
            'builtInControls',
            'customAuthenticationFactors',
            'operator',
            'termsOfUse'
        ) `
        -Label 'grant controls'
}

$policiesUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
$strengthsUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies'
$strengths = @(Get-GraphCollection -Uri $strengthsUri)
$strengthMatches = @($strengths | Where-Object {
    $_.displayName -eq 'Phishing-resistant MFA' -and $_.policyType -eq 'builtIn'
})
if ($strengthMatches.Count -ne 1) {
    throw "Expected exactly one built-in 'Phishing-resistant MFA' authentication strength."
}
$strength = $strengthMatches[0]

function Assert-ConditionalAccessOperation {
    param([Parameter(Mandatory)][Collections.IDictionary]$Operation)

    $operationId = [guid]::Empty
    if (
        [int]$Operation.schemaVersion -ne 1 -or
        $Operation.status -cne 'provisioning' -or
        -not [guid]::TryParseExact(
            [string]$Operation.operationId,
            'D',
            [ref]$operationId
        ) -or
        $Operation.policyDisplayName -cne
            "$PolicyDisplayName [$($operationId.ToString('N'))]" -or
        $Operation.requestedPolicyDisplayName -cne $PolicyDisplayName -or
        $Operation.tenantId -ine $TenantId -or
        $Operation.applicationId -ine $application.appId -or
        $Operation.groupId -ine $entra.groupId -or
        $Operation.authenticationStrengthId -ine $strength.id -or
        $Operation.policyStatus -notin @('pending', 'planned', 'created')
    ) {
        throw 'Conditional Access journal does not match the exact requested policy contract.'
    }
}

$conditionalAccessOperation = if (
    Test-Path -LiteralPath $conditionalAccessOperationPath -PathType Leaf
) {
    Get-Content -LiteralPath $conditionalAccessOperationPath -Raw |
        ConvertFrom-Json -AsHashtable
}
else {
    $null
}
if ($existingConditionalAccessState) {
    $effectivePolicyDisplayName = [string]$existingConditionalAccessState.policyDisplayName
    if (
        $existingConditionalAccessState.PSObject.Properties.Name -contains
            'requestedPolicyDisplayName' -and
        $existingConditionalAccessState.requestedPolicyDisplayName -cne
            $PolicyDisplayName
    ) {
        throw 'Recorded Conditional Access state belongs to another requested policy name.'
    }
    if ($conditionalAccessOperation) {
        Assert-ConditionalAccessOperation -Operation $conditionalAccessOperation
        if (
            $conditionalAccessOperation.policyStatus -cne 'created' -or
            $conditionalAccessOperation.policyId -ine
                $existingConditionalAccessState.policyId -or
            $conditionalAccessOperation.policyDisplayName -cne
                $existingConditionalAccessState.policyDisplayName
        ) {
            throw 'Retained Conditional Access journal does not match the final policy state.'
        }
    }
}
else {
    if (-not $conditionalAccessOperation) {
        $operationId = [guid]::NewGuid()
        $conditionalAccessOperation = [ordered]@{
            applicationId = $application.appId
            authenticationStrengthId = $strength.id
            groupId = $entra.groupId
            operationId = $operationId.ToString('D')
            policyDisplayName = "$PolicyDisplayName [$($operationId.ToString('N'))]"
            policyId = $null
            policyStatus = 'pending'
            requestedPolicyDisplayName = $PolicyDisplayName
            schemaVersion = 1
            status = 'provisioning'
            tenantId = $TenantId
        }
    }
    Assert-ConditionalAccessOperation -Operation $conditionalAccessOperation
    if ($provisionalConditionalAccessState -and (
        [int]$provisionalConditionalAccessState.schemaVersion -ne 2 -or
        $provisionalConditionalAccessState.policyCreated -ne $true -or
        $provisionalConditionalAccessState.policyState -cne
            'creationPendingReadback' -or
        $provisionalConditionalAccessState.tenantId -ine $TenantId -or
        $provisionalConditionalAccessState.applicationId -ine $application.appId -or
        $provisionalConditionalAccessState.groupId -ine $entra.groupId -or
        $provisionalConditionalAccessState.authenticationStrengthId -ine $strength.id -or
        $provisionalConditionalAccessState.policyId -ine
            $conditionalAccessOperation.policyId -or
        $provisionalConditionalAccessState.policyDisplayName -cne
            $conditionalAccessOperation.policyDisplayName -or
        $provisionalConditionalAccessState.requestedPolicyDisplayName -cne
            $PolicyDisplayName
    )) {
        throw 'Provisional Conditional Access state does not match its creation journal.'
    }
    Write-ConditionalAccessState `
        -StateRecord $conditionalAccessOperation `
        -Path $conditionalAccessOperationPath
    $effectivePolicyDisplayName = [string]$conditionalAccessOperation.policyDisplayName
}

$matchingPolicies = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $policiesUri) | Where-Object {
        $_.displayName -ceq $effectivePolicyDisplayName
    }
} -WaitForAppearance:(
    $conditionalAccessOperation -and
    $conditionalAccessOperation.policyStatus -in @('planned', 'created')
))
if ($matchingPolicies.Count -gt 1) {
    throw "More than one Conditional Access policy is named '$effectivePolicyDisplayName'."
}
if ($matchingPolicies.Count -eq 1 -and -not $existingConditionalAccessState) {
    if (
        $conditionalAccessOperation.policyId -and
        $matchingPolicies[0].id -ine $conditionalAccessOperation.policyId
    ) {
        throw 'The Conditional Access journal identifies another policy object.'
    }
    Assert-LabPolicy `
        -Policy $matchingPolicies[0] `
        -GroupId $entra.groupId `
        -ApplicationId $application.appId `
        -AuthenticationStrengthId $strength.id
    if ($matchingPolicies[0].state -cne 'disabled') {
        throw 'Recovered Conditional Access policy is not disabled.'
    }
    $conditionalAccessOperation.policyId = $matchingPolicies[0].id
    $conditionalAccessOperation.policyStatus = 'created'
    Write-ConditionalAccessState `
        -StateRecord $conditionalAccessOperation `
        -Path $conditionalAccessOperationPath
}
if ($existingConditionalAccessState -and $matchingPolicies.Count -eq 0) {
    throw 'The recorded Conditional Access policy no longer exists; refusing to create a replacement.'
}
if ($existingConditionalAccessState -and -not [bool]$existingConditionalAccessState.policyCreated) {
    throw 'Recorded state does not prove that this solution created the Conditional Access policy.'
}

$policyBody = @{
    displayName = $effectivePolicyDisplayName
    state = 'disabled'
    conditions = @{
        applications = @{
            excludeApplications = @()
            includeApplications = @($application.appId)
        }
        clientAppTypes = @('all')
        users = @{
            excludeGroups = @()
            excludeRoles = @()
            excludeUsers = @()
            includeGroups = @($entra.groupId)
            includeRoles = @()
            includeUsers = @()
        }
    }
    grantControls = @{
        authenticationStrength = @{
            id = $strength.id
        }
        operator = 'OR'
    }
}

$policyCreated = $false
$originalPolicyState = $null
if ($matchingPolicies.Count -eq 0) {
    if (
        $conditionalAccessOperation.policyId -or
        $conditionalAccessOperation.policyStatus -ceq 'created'
    ) {
        throw 'The exact journaled Conditional Access policy no longer exists.'
    }
    $conditionalAccessOperation.policyStatus = 'planned'
    Write-ConditionalAccessState `
        -StateRecord $conditionalAccessOperation `
        -Path $conditionalAccessOperationPath
    $policy = Invoke-GraphJson -Method POST -Uri $policiesUri -Body $policyBody
    $policyCreated = $true
    if ([string]$policy.id -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'Microsoft Graph did not return a valid policy ID for the new disabled policy.'
    }
    $policyUri = "$policiesUri/$($policy.id)"
    $conditionalAccessOperation.policyId = $policy.id
    $conditionalAccessOperation.policyStatus = 'created'
    Write-ConditionalAccessState `
        -StateRecord $conditionalAccessOperation `
        -Path $conditionalAccessOperationPath
    $provisionalState = New-ConditionalAccessStateRecord `
        -PolicyId $policy.id `
        -PolicyCreated $true `
        -PolicyOriginalState $null `
        -PolicyState 'creationPendingReadback'
    try {
        Write-ConditionalAccessState -StateRecord $provisionalState
    }
    catch {
        throw [InvalidOperationException]::new(
            (
                "Writing final cleanup metadata for policy '$($policy.id)' failed; " +
                'the deterministic creation journal was retained for a safe rerun.'
            ),
            $_.Exception
        )
    }
} else {
    $policy = $matchingPolicies[0]
    $policyCreated = [bool]$conditionalAccessOperation
    $originalPolicyState = if ($existingConditionalAccessState) {
        $policy.state
    }
    else {
        $null
    }
    Assert-LabPolicy `
        -Policy $policy `
        -GroupId $entra.groupId `
        -ApplicationId $application.appId `
        -AuthenticationStrengthId $strength.id
}
if ($existingConditionalAccessState -and (
    $existingConditionalAccessState.tenantId -ne $TenantId -or
    $existingConditionalAccessState.applicationId -ne $application.appId -or
    $existingConditionalAccessState.groupId -ne $entra.groupId -or
    $existingConditionalAccessState.policyId -ne $policy.id -or
    $existingConditionalAccessState.policyDisplayName -cne $effectivePolicyDisplayName
)) {
    throw 'Existing Conditional Access state does not match the exact lab policy.'
}

$policyUri = "$policiesUri/$($policy.id)"
$policy = Get-ConditionalAccessPolicy -Uri $policyUri
Assert-LabPolicy `
    -Policy $policy `
    -GroupId $entra.groupId `
    -ApplicationId $application.appId `
    -AuthenticationStrengthId $strength.id

$recordedPolicyCreated = if ($existingConditionalAccessState) {
        [bool]$existingConditionalAccessState.policyCreated
    } else {
        $policyCreated
    }
$recordedOriginalState = if ($existingConditionalAccessState) {
        $existingConditionalAccessState.policyOriginalState
    } else {
        $originalPolicyState
    }
$stateRecord = New-ConditionalAccessStateRecord `
    -PolicyId $policy.id `
    -PolicyCreated $recordedPolicyCreated `
    -PolicyOriginalState $recordedOriginalState `
    -PolicyState $policy.state

$verifiedPolicy = $policy
$stateCommitCompleted = $false
if ($policy.state -ne $State) {
    $preTransitionState = $policy.state

    try {
        Write-ConditionalAccessState -StateRecord $stateRecord
        $stateRecord.policyState = "transitionPending:$State"
        $stateRecord.verifiedAt = (Get-Date).ToString('o')
        Write-ConditionalAccessState -StateRecord $stateRecord

        Invoke-GraphJson -Method PATCH -Uri $policyUri -Body @{ state = $State } | Out-Null
        $verifiedPolicy = Get-ConditionalAccessPolicy -Uri $policyUri -ExpectedState $State
        Assert-LabPolicy `
            -Policy $verifiedPolicy `
            -GroupId $entra.groupId `
            -ApplicationId $application.appId `
            -AuthenticationStrengthId $strength.id
        if ($verifiedPolicy.state -ne $State) {
            throw "Conditional Access policy state is '$($verifiedPolicy.state)', not '$State'."
        }
        $stateRecord.policyState = $verifiedPolicy.state
        $stateRecord.verifiedAt = (Get-Date).ToString('o')
        Write-ConditionalAccessState -StateRecord $stateRecord
        $stateCommitCompleted = $true
    } catch {
        $transitionError = $_
        $recoveryState = if ($State -eq 'enabled') {
            $preTransitionState
        } else {
            $State
        }
        $stateRecord.policyState = 'transitionUnverified'
        $stateRecord.verifiedAt = (Get-Date).ToString('o')
        $transitionStateWriteError = $null
        try {
            Write-ConditionalAccessState -StateRecord $stateRecord
        } catch {
            $transitionStateWriteError = $_
        }

        try {
            Invoke-GraphJson -Method PATCH -Uri $policyUri -Body @{ state = $recoveryState } | Out-Null
            $recoveredPolicy = Get-ConditionalAccessPolicy `
                -Uri $policyUri `
                -ExpectedState $recoveryState
            Assert-LabPolicy `
                -Policy $recoveredPolicy `
                -GroupId $entra.groupId `
                -ApplicationId $application.appId `
                -AuthenticationStrengthId $strength.id
            $stateRecord.policyState = $recoveredPolicy.state
            $stateRecord.verifiedAt = (Get-Date).ToString('o')
            Write-ConditionalAccessState -StateRecord $stateRecord
        } catch {
            throw (
                "Conditional Access transition to '$State' failed: " +
                "$($transitionError.Exception.Message) Recovery verification or persistence " +
                "for '$recoveryState' also failed: " +
                "$($_.Exception.Message) Exact cleanup metadata remains at '$conditionalAccessStatePath'."
            )
        }
        if ($transitionStateWriteError) {
            throw (
                "Conditional Access transition to '$State' failed and recovery to " +
                "'$recoveryState' succeeded, but writing transitional cleanup metadata failed: " +
                "$($transitionStateWriteError.Exception.Message)"
            )
        }
        throw $transitionError
    }
}

Assert-LabPolicy `
    -Policy $verifiedPolicy `
    -GroupId $entra.groupId `
    -ApplicationId $application.appId `
    -AuthenticationStrengthId $strength.id
if ($verifiedPolicy.state -ne $State) {
    throw "Conditional Access policy state is '$($verifiedPolicy.state)', not '$State'."
}

if (-not $stateCommitCompleted) {
    $stateRecord.policyState = $verifiedPolicy.state
    $stateRecord.verifiedAt = (Get-Date).ToString('o')
    Write-ConditionalAccessState -StateRecord $stateRecord
}
if (Test-Path -LiteralPath $conditionalAccessOperationPath) {
    Remove-Item -LiteralPath $conditionalAccessOperationPath -Force
}

Write-Host "Conditional Access policy '$effectivePolicyDisplayName' is '$State'."
}
finally {
    $conditionalAccessOperationLock.Dispose()
}
Write-Host "Target group: $($entra.groupId)"
Write-Host "Target application: $($application.appId)"
Write-Host "Grant: $($strength.displayName) ($($strength.id))"
