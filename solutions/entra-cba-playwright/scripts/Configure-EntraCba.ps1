[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$TestUserUpn,
    [string]$TestUserDisplayName = 'CBA Playwright Test User',
    [string]$GroupDisplayName = 'grp-entra-cba-playwright-poc',
    [string]$PkiDisplayName = 'Entra CBA Playwright POC PKI',
    [switch]$Connect
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$pkiStatePath = Join-Path $stateDirectory 'pki.json'
$baselinePolicyPath = Join-Path $stateDirectory 'x509-policy-baseline.json'
$baselinePkiPath = Join-Path $stateDirectory 'pki-baseline.json'
$baselineContextPath = Join-Path $stateDirectory 'entra-baseline-context.json'
$baselineOperationPath = Join-Path $stateDirectory 'entra-baseline-operation.json'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$entraOperationStatePath = Join-Path $stateDirectory 'entra-operation.json'
$entraOperationLockPath = Join-Path $stateDirectory 'entra-operation.lock'
try {
    $entraOperationLock = [IO.File]::Open(
        $entraOperationLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another Entra configuration or teardown transaction owns the local lock.'
}
try {
. (Join-Path $PSScriptRoot 'EntraCba-Policy.ps1')

function Write-EntraStateAtomically {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Collections.IDictionary]$State
    )

    $operationId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$Path.$operationId.tmp"
    $backupPath = "$Path.$operationId.bak"
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

function Write-EntraTextAtomically {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )

    $writeId = "$PID.$([guid]::NewGuid().ToString('N'))"
    $temporaryPath = "$Path.$writeId.tmp"
    $backupPath = "$Path.$writeId.bak"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            $Text,
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

function Get-EntraTextSha256 {
    param([Parameter(Mandatory)][string]$Text)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString(
            $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        ).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

if (-not (Test-Path $pkiStatePath)) {
    throw "PKI state not found at '$pkiStatePath'."
}

$pkiState = Get-Content $pkiStatePath -Raw | ConvertFrom-Json
if ($pkiState.testUserUpn -ne $TestUserUpn) {
    throw "The generated certificate belongs to '$($pkiState.testUserUpn)', not '$TestUserUpn'."
}

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
$requiredScopes = @(
    'Group.ReadWrite.All',
    'Policy.ReadWrite.AuthenticationMethod',
    'PublicKeyInfrastructure.ReadWrite.All',
    'User.ReadWrite.All'
)
$context = Get-MgContext
$missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
if (-not $context -or $context.TenantId -ne $TenantId -or $missingScopes.Count -ne 0) {
    if (-not $Connect) {
        throw "No reusable Microsoft Graph context for tenant '$TenantId' has scopes: $($requiredScopes -join ', '). Rerun with -Connect to authorize once in the system browser."
    }
    Connect-MgGraph `
        -TenantId $TenantId `
        -Scopes $requiredScopes `
        -ClientTimeout 600 `
        -ContextScope CurrentUser `
        -NoWelcome
    $context = Get-MgContext
    $missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
}
if (-not $context -or $context.TenantId -ne $TenantId -or $missingScopes.Count -ne 0) {
    throw "Microsoft Graph authorization for '$($requiredScopes -join ', ')' in tenant '$TenantId' is required."
}

function Get-GraphCollectionResponse {
    param([Parameter(Mandatory)][string]$Uri)

    $firstResponse = $null
    $items = [Collections.Generic.List[object]]::new()
    while ($Uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri
        if (-not $firstResponse) {
            $firstResponse = $response
        }
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
    if (-not $firstResponse) {
        throw 'Microsoft Graph returned no collection response.'
    }
    $firstResponse.value = $items.ToArray()
    if ($firstResponse -is [Collections.IDictionary]) {
        $firstResponse.Remove('@odata.nextLink')
    } else {
        $firstResponse.PSObject.Properties.Remove('@odata.nextLink')
    }
    return $firstResponse
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)

    return @((Get-GraphCollectionResponse -Uri $Uri).value)
}

$policyUri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate'
$pkiCollectionUri = 'https://graph.microsoft.com/v1.0/directory/publicKeyInfrastructure/certificateBasedAuthConfigurations'

$existingPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
$existingPkis = Get-GraphCollectionResponse -Uri $pkiCollectionUri

if (Test-Path -LiteralPath $baselineOperationPath -PathType Leaf) {
    $baselineOperation = Get-Content -LiteralPath $baselineOperationPath -Raw |
        ConvertFrom-Json
    if (
        [int]$baselineOperation.schemaVersion -ne 1 -or
        $baselineOperation.status -cne 'capturing' -or
        $baselineOperation.tenantId -ine $TenantId -or
        (Get-EntraTextSha256 -Text ([string]$baselineOperation.policyJson)) -cne
            $baselineOperation.policySha256 -or
        (Get-EntraTextSha256 -Text ([string]$baselineOperation.pkiJson)) -cne
            $baselineOperation.pkiSha256
    ) {
        throw 'Entra baseline capture journal is invalid or belongs to another tenant.'
    }
    foreach ($baselineFile in @(
        @{
            path = $baselinePolicyPath
            text = [string]$baselineOperation.policyJson
            sha256 = [string]$baselineOperation.policySha256
        }
        @{
            path = $baselinePkiPath
            text = [string]$baselineOperation.pkiJson
            sha256 = [string]$baselineOperation.pkiSha256
        }
    )) {
        if (
            (Test-Path -LiteralPath $baselineFile.path -PathType Leaf) -and
            (Get-FileHash -LiteralPath $baselineFile.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $baselineFile.sha256
        ) {
            throw 'A partially captured Entra baseline differs from its recovery journal.'
        }
        if (-not (Test-Path -LiteralPath $baselineFile.path -PathType Leaf)) {
            Write-EntraTextAtomically `
                -Path $baselineFile.path `
                -Text $baselineFile.text
        }
    }
    $recoveredBaselineContext = [ordered]@{
        capturedAt = [string]$baselineOperation.capturedAt
        pkiSha256 = [string]$baselineOperation.pkiSha256
        policySha256 = [string]$baselineOperation.policySha256
        tenantId = $TenantId
    }
    if (Test-Path -LiteralPath $baselineContextPath -PathType Leaf) {
        $currentBaselineContext = Get-Content `
            -LiteralPath $baselineContextPath `
            -Raw | ConvertFrom-Json
        if (
            $currentBaselineContext.tenantId -ine $TenantId -or
            $currentBaselineContext.policySha256 -cne
                $recoveredBaselineContext.policySha256 -or
            $currentBaselineContext.pkiSha256 -cne
                $recoveredBaselineContext.pkiSha256
        ) {
            throw 'Existing Entra baseline context differs from its recovery journal.'
        }
    }
    else {
        Write-EntraStateAtomically `
            -Path $baselineContextPath `
            -State $recoveredBaselineContext
    }
    Remove-Item -LiteralPath $baselineOperationPath -Force
}

$existingState = if (Test-Path $entraStatePath) {
    Get-Content $entraStatePath -Raw | ConvertFrom-Json -AsHashtable
} else {
    $null
}
$entraOperation = if (Test-Path -LiteralPath $entraOperationStatePath -PathType Leaf) {
    Get-Content -LiteralPath $entraOperationStatePath -Raw |
        ConvertFrom-Json -AsHashtable
}
else {
    $null
}
if ($existingState) {
    if (
        $existingState.tenantId -ne $TenantId -or
        $existingState.testUserUpn -ne $TestUserUpn -or
        $existingState.groupDisplayName -cne $GroupDisplayName -or
        [string]::IsNullOrWhiteSpace([string]$existingState.testUserId) -or
        [string]::IsNullOrWhiteSpace([string]$existingState.groupId)
    ) {
        throw 'Recorded Entra state does not match the requested tenant, test user, and group.'
    }
    if (
        $existingState.ContainsKey('status') -and
        $existingState.status -cne 'verified'
    ) {
        throw 'Recorded Entra state is not fully verified.'
    }
    if (
        -not [bool]$existingState.testUserCreated -or
        -not [bool]$existingState.groupCreated -or
        -not [bool]$existingState.membershipAdded
    ) {
        throw (
            'Recorded state does not prove that this solution created the test user, group, and ' +
            'membership. Use a new dedicated UPN and group instead of adopting existing objects.'
        )
    }
}
if ($entraOperation) {
    $operationId = [guid]::Empty
    if (
        [int]$entraOperation.schemaVersion -ne 1 -or
        $entraOperation.status -cne 'provisioning' -or
        -not [guid]::TryParseExact(
            [string]$entraOperation.operationId,
            'D',
            [ref]$operationId
        ) -or
        $entraOperation.ownershipMarker -cne
            "entra-cba-playwright/$($operationId.ToString('D'))" -or
        $entraOperation.tenantId -ine $TenantId -or
        $entraOperation.testUserUpn -ine $TestUserUpn -or
        $entraOperation.testUserDisplayName -cne $TestUserDisplayName -or
        $entraOperation.groupDisplayName -cne $GroupDisplayName -or
        $entraOperation.requestedPkiDisplayName -cne $PkiDisplayName -or
        $entraOperation.pkiObjectDisplayName -cne
            "$PkiDisplayName [$($operationId.ToString('N'))]"
    ) {
        throw 'Entra provisioning journal does not match the exact requested ownership contract.'
    }
}

if ($existingState -or $entraOperation) {
    foreach ($baselinePath in @($baselinePolicyPath, $baselinePkiPath)) {
        if (-not (Test-Path -LiteralPath $baselinePath -PathType Leaf)) {
            throw "Recorded Entra state is missing bound baseline file '$baselinePath'."
        }
    }
    if (-not (Test-Path -LiteralPath $baselineContextPath -PathType Leaf)) {
        Get-Content -LiteralPath $baselinePolicyPath -Raw | ConvertFrom-Json | Out-Null
        Get-Content -LiteralPath $baselinePkiPath -Raw | ConvertFrom-Json | Out-Null
        $legacyBaselineContext = [ordered]@{
            capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
            migratedFromLegacyState = $true
            pkiSha256 = (
                Get-FileHash -LiteralPath $baselinePkiPath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            policySha256 = (
                Get-FileHash -LiteralPath $baselinePolicyPath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            tenantId = if ($existingState) {
                $existingState.tenantId
            }
            else {
                $entraOperation.tenantId
            }
        }
        $legacyBaselineContext |
            ConvertTo-Json |
            Set-Content -LiteralPath $baselineContextPath -Encoding utf8NoBOM
    }
    $baselineContext = Get-Content -LiteralPath $baselineContextPath -Raw | ConvertFrom-Json
    $policyBaselineHash = (
        Get-FileHash -LiteralPath $baselinePolicyPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $pkiBaselineHash = (
        Get-FileHash -LiteralPath $baselinePkiPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (
        $baselineContext.tenantId -ne $TenantId -or
        $baselineContext.policySha256 -cne $policyBaselineHash -or
        $baselineContext.pkiSha256 -cne $pkiBaselineHash
    ) {
        throw 'The saved Entra baseline is not bound intact to the requested tenant.'
    }
}
else {
    $reusePriorBaseline = $false
    if (Test-Path -LiteralPath $baselineContextPath -PathType Leaf) {
        foreach ($baselinePath in @($baselinePolicyPath, $baselinePkiPath)) {
            if (-not (Test-Path -LiteralPath $baselinePath -PathType Leaf)) {
                throw "Bound baseline context is missing '$baselinePath'."
            }
        }
        $priorBaselineContext = Get-Content -LiteralPath $baselineContextPath -Raw |
            ConvertFrom-Json
        $policyBaselineHash = (
            Get-FileHash -LiteralPath $baselinePolicyPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $pkiBaselineHash = (
            Get-FileHash -LiteralPath $baselinePkiPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if (
            $priorBaselineContext.tenantId -ne $TenantId -or
            $priorBaselineContext.policySha256 -cne $policyBaselineHash -or
            $priorBaselineContext.pkiSha256 -cne $pkiBaselineHash
        ) {
            throw 'Prior baseline state belongs to another tenant or failed its integrity binding.'
        }
        $priorPolicy = Get-Content -LiteralPath $baselinePolicyPath -Raw |
            ConvertFrom-Json
        $priorPkis = Get-Content -LiteralPath $baselinePkiPath -Raw |
            ConvertFrom-Json
        if (
            ($priorPolicy | ConvertTo-Json -Depth 20 -Compress) -cne
                ($existingPolicy | ConvertTo-Json -Depth 20 -Compress) -or
            ($priorPkis | ConvertTo-Json -Depth 20 -Compress) -cne
                ($existingPkis | ConvertTo-Json -Depth 20 -Compress)
        ) {
            throw (
                'Live Entra CBA state differs from the prior baseline while no owned lab state ' +
                'exists. Manual recovery is required.'
            )
        }
        $reusePriorBaseline = $true
    }
    elseif (
        (Test-Path -LiteralPath $baselinePolicyPath) -or
        (Test-Path -LiteralPath $baselinePkiPath)
    ) {
        throw 'Unbound baseline files already exist; manual review is required before configuration.'
    }

    if (-not $reusePriorBaseline) {
        $policyBaselineJson = $existingPolicy | ConvertTo-Json -Depth 20
        $pkiBaselineJson = $existingPkis | ConvertTo-Json -Depth 20
        $baselineOperation = [ordered]@{
            capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
            pkiJson = $pkiBaselineJson
            pkiSha256 = Get-EntraTextSha256 -Text $pkiBaselineJson
            policyJson = $policyBaselineJson
            policySha256 = Get-EntraTextSha256 -Text $policyBaselineJson
            schemaVersion = 1
            status = 'capturing'
            tenantId = $TenantId
        }
        Write-EntraStateAtomically `
            -Path $baselineOperationPath `
            -State $baselineOperation
        Write-EntraTextAtomically `
            -Path $baselinePolicyPath `
            -Text $policyBaselineJson
        Write-EntraTextAtomically `
            -Path $baselinePkiPath `
            -Text $pkiBaselineJson
        $baselineContext = [ordered]@{
            capturedAt = $baselineOperation.capturedAt
            pkiSha256 = $baselineOperation.pkiSha256
            policySha256 = $baselineOperation.policySha256
            tenantId = $TenantId
        }
        Write-EntraStateAtomically `
            -Path $baselineContextPath `
            -State $baselineContext
        Remove-Item -LiteralPath $baselineOperationPath -Force
    }
}

if (-not $existingState -and -not $entraOperation) {
    $operationId = [guid]::NewGuid()
    $pkiObjectDisplayName = "$PkiDisplayName [$($operationId.ToString('N'))]"
    if ($pkiObjectDisplayName.Length -gt 250) {
        throw 'The PKI display name is too long for a recovery-bound object name.'
    }
    $entraOperation = [ordered]@{
        baselinePkiSha256 = (
            Get-FileHash -LiteralPath $baselinePkiPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        baselinePolicySha256 = (
            Get-FileHash -LiteralPath $baselinePolicyPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        caCreated = $false
        caId = $null
        caStatus = 'pending'
        groupCreated = $false
        groupDisplayName = $GroupDisplayName
        groupId = $null
        groupStatus = 'pending'
        membershipAdded = $false
        membershipStatus = 'pending'
        operationId = $operationId.ToString('D')
        ownershipMarker = "entra-cba-playwright/$($operationId.ToString('D'))"
        pkiCreated = $false
        pkiId = $null
        pkiObjectDisplayName = $pkiObjectDisplayName
        pkiStatus = 'pending'
        policyOid = $pkiState.policyOid
        policyStatus = 'pending'
        requestedPkiDisplayName = $PkiDisplayName
        schemaVersion = 1
        status = 'provisioning'
        testUserCreated = $false
        testUserDisplayName = $TestUserDisplayName
        testUserId = $null
        testUserStatus = 'pending'
        testUserUpn = $TestUserUpn
        tenantId = $TenantId
    }
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
}
if ($entraOperation) {
    if (
        $entraOperation.baselinePolicySha256 -cne (
            Get-FileHash -LiteralPath $baselinePolicyPath -Algorithm SHA256
        ).Hash.ToLowerInvariant() -or
        $entraOperation.baselinePkiSha256 -cne (
            Get-FileHash -LiteralPath $baselinePkiPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    ) {
        throw 'Entra provisioning journal is not bound to the intact tenant baseline.'
    }
    $effectivePkiDisplayName = [string]$entraOperation.pkiObjectDisplayName
}
else {
    $effectivePkiDisplayName = [string]$existingState.pkiDisplayName
    if (
        $existingState.ContainsKey('requestedPkiDisplayName') -and
        $existingState.requestedPkiDisplayName -cne $PkiDisplayName
    ) {
        throw 'Recorded Entra state belongs to a different requested PKI display name.'
    }
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
    throw 'Microsoft Graph object absence could not be proven after the appearance window.'
}

$escapedGroupName = [Uri]::EscapeDataString("displayName eq '$($GroupDisplayName.Replace("'", "''"))'")
$groupQueryUri = "https://graph.microsoft.com/v1.0/groups?`$filter=$escapedGroupName&`$select=id,displayName,description,securityEnabled"
$groups = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $groupQueryUri)
} -WaitForAppearance:(
    $entraOperation -and
    $entraOperation.groupStatus -in @('planned', 'created')
))
if ($groups.Count -gt 1) {
    throw "More than one group matched '$GroupDisplayName'."
}
if ($groups.Count -eq 1) {
    if ($existingState -and $groups[0].id -ne $existingState.groupId) {
        throw (
            "Group '$GroupDisplayName' already exists but is not bound to this solution's exact " +
            'recorded object ID. Choose a new dedicated group name.'
        )
    }
    if ($entraOperation -and (
        $groups[0].description -cne $entraOperation.ownershipMarker -or
        (
            $entraOperation.groupId -and
            $groups[0].id -ne $entraOperation.groupId
        )
    )) {
        throw 'The existing group does not match the provisioning ownership marker and object ID.'
    }
    if (-not $groups[0].securityEnabled) {
        throw "Existing group '$GroupDisplayName' is not security-enabled."
    }
    if ($entraOperation) {
        $entraOperation.groupCreated = $true
        $entraOperation.groupId = $groups[0].id
        $entraOperation.groupStatus = 'created'
        Write-EntraStateAtomically `
            -Path $entraOperationStatePath `
            -State $entraOperation
    }
}
elseif (
    $existingState -or
    (
        $entraOperation -and
        ($entraOperation.groupId -or $entraOperation.groupStatus -ceq 'created')
    )
) {
    throw 'The exact recorded lab group no longer exists; refusing to create a replacement implicitly.'
}

$knownLabGroupId = if ($existingState) {
    $existingState.groupId
}
elseif ($entraOperation) {
    $entraOperation.groupId
}

$foreignTargets = @(
    @($existingPolicy.includeTargets) | Where-Object {
        -not $knownLabGroupId -or $_.id -ne $knownLabGroupId
    }
)
if ($existingPolicy.state -eq 'enabled' -and $foreignTargets.Count -gt 0) {
    throw 'CBA is already enabled for another target; refusing to modify an active tenant-wide policy.'
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

function New-RandomPassword {
    $bytes = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    try {
        return "$([Convert]::ToHexString($bytes))aA1!"
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

$userCreated = [bool]($entraOperation -and $entraOperation.testUserCreated)
$groupCreated = [bool]($entraOperation -and $entraOperation.groupCreated)
$membershipAdded = [bool]($entraOperation -and $entraOperation.membershipAdded)
$pkiCreated = [bool]($entraOperation -and $entraOperation.pkiCreated)
$caCreated = [bool]($entraOperation -and $entraOperation.caCreated)
$policyMutationAttempted = $false
$policyRollbackBody = ConvertTo-X509PolicyPatchBody -Policy $existingPolicy
try {
$escapedUpn = [Uri]::EscapeDataString("userPrincipalName eq '$($TestUserUpn.Replace("'", "''"))'")
$userQueryUri = "https://graph.microsoft.com/v1.0/users?`$filter=$escapedUpn&`$select=id,displayName,userPrincipalName,accountEnabled,employeeType"
$users = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $userQueryUri)
} -WaitForAppearance:(
    $entraOperation -and
    $entraOperation.testUserStatus -in @('planned', 'created')
))

if ($users.Count -gt 1) {
    throw "More than one user matched '$TestUserUpn'."
}
if ($users.Count -eq 1) {
    if ($existingState -and $users[0].id -ne $existingState.testUserId) {
        throw (
            "User '$TestUserUpn' already exists but is not bound to this solution's exact recorded " +
            'object ID. Choose a new dedicated test-user UPN.'
        )
    }
    if ($entraOperation -and (
        $users[0].employeeType -cne $entraOperation.ownershipMarker -or
        (
            $entraOperation.testUserId -and
            $users[0].id -ne $entraOperation.testUserId
        )
    )) {
        throw 'The existing user does not match the provisioning ownership marker and object ID.'
    }
    if (-not [bool]$users[0].accountEnabled) {
        throw "The exact recorded test user '$TestUserUpn' is disabled."
    }
    if ($entraOperation) {
        $entraOperation.testUserCreated = $true
        $entraOperation.testUserId = $users[0].id
        $entraOperation.testUserStatus = 'created'
        Write-EntraStateAtomically `
            -Path $entraOperationStatePath `
            -State $entraOperation
        $userCreated = $true
    }
}
elseif (
    $existingState -or
    (
        $entraOperation -and
        (
            $entraOperation.testUserId -or
            $entraOperation.testUserStatus -ceq 'created'
        )
    )
) {
    throw 'The exact recorded lab user no longer exists; refusing to create a replacement implicitly.'
}

if ($users.Count -eq 0) {
    $entraOperation.testUserStatus = 'planned'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
    $password = New-RandomPassword
    try {
        $user = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body @{
            accountEnabled = $true
            displayName = $TestUserDisplayName
            employeeType = $entraOperation.ownershipMarker
            mailNickname = 'cba-playwright-test'
            passwordProfile = @{
                forceChangePasswordNextSignIn = $false
                password = $password
            }
            userPrincipalName = $TestUserUpn
        }
    } finally {
        $password = $null
    }
    if (-not $user.id) {
        throw 'User creation did not return an object ID; recovery state remains planned.'
    }
    $userCreated = $true
    $entraOperation.testUserCreated = $true
    $entraOperation.testUserId = $user.id
    $entraOperation.testUserStatus = 'created'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
} else {
    $user = $users[0]
}

if ($groups.Count -eq 0) {
    $entraOperation.groupStatus = 'planned'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
    $group = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/groups' -Body @{
        description = $entraOperation.ownershipMarker
        displayName = $GroupDisplayName
        groupTypes = @()
        mailEnabled = $false
        mailNickname = 'grp-entra-cba-playwright-poc'
        securityEnabled = $true
    }
    if (-not $group.id) {
        throw 'Group creation did not return an object ID; recovery state remains planned.'
    }
    $groupCreated = $true
    $entraOperation.groupCreated = $true
    $entraOperation.groupId = $group.id
    $entraOperation.groupStatus = 'created'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
} else {
    $group = $groups[0]
}

$membersUri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id&`$top=999"
$members = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $membersUri)
} -WaitForAppearance:(
    $entraOperation -and
    $entraOperation.membershipStatus -in @('planned', 'created')
))
$foreignMembers = @($members | Where-Object { $_.id -ne $user.id })
if ($foreignMembers.Count -ne 0) {
    throw "Group '$GroupDisplayName' contains $($foreignMembers.Count) non-lab member(s); refusing to expand CBA scope."
}
if ($user.id -notin $members.id) {
    if (
        $entraOperation -and
        (
            $entraOperation.membershipAdded -or
            $entraOperation.membershipStatus -ceq 'created'
        )
    ) {
        throw 'The exact recorded lab group membership no longer exists.'
    }
    if ($entraOperation) {
        $entraOperation.membershipStatus = 'planned'
        Write-EntraStateAtomically `
            -Path $entraOperationStatePath `
            -State $entraOperation
    }
    Invoke-GraphJson `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/`$ref" `
        -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)" } | Out-Null
    $membershipAdded = $true
}
$verifiedMembers = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $membersUri)
} -WaitForAppearance)
if ($verifiedMembers.Count -ne 1 -or $verifiedMembers[0].id -ne $user.id) {
    throw "Group '$GroupDisplayName' must contain only the dedicated test user."
}
if ($entraOperation) {
    $entraOperation.membershipAdded = $true
    $entraOperation.membershipStatus = 'created'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
    $membershipAdded = $true
}

$authenticationModeConfiguration = @{
    x509CertificateAuthenticationDefaultMode = 'x509CertificateSingleFactor'
    rules = @(
        @{
            identifier = $pkiState.policyOid
            x509CertificateAuthenticationMode = 'x509CertificateMultiFactor'
            x509CertificateRuleType = 'policyOID'
        }
    )
}

$basePolicyBody = @{
    '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'
    id = 'X509Certificate'
    state = 'enabled'
    includeTargets = @(
        @{
            id = $group.id
            isRegistrationRequired = $false
            targetType = 'group'
        }
    )
    excludeTargets = @()
    certificateUserBindings = @(
        @{
            priority = 1
            userProperty = 'userPrincipalName'
            x509CertificateField = 'PrincipalName'
        }
    )
    authenticationModeConfiguration = $authenticationModeConfiguration
    issuerHintsConfiguration = @{ state = 'disabled' }
    crlValidationConfiguration = @{
        state = 'enabled'
        exemptedCertificateAuthoritiesSubjectKeyIdentifiers = @()
    }
}

$matchingPkis = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $pkiCollectionUri) | Where-Object {
        $_.displayName -ceq $effectivePkiDisplayName
    }
} -WaitForAppearance:(
    $entraOperation -and
    $entraOperation.pkiStatus -in @('planned', 'created')
))
if ($matchingPkis.Count -gt 1) {
    throw "More than one PKI container is named '$effectivePkiDisplayName'."
}

if ($matchingPkis.Count -eq 0) {
    if (
        $existingState -or
        (
            $entraOperation -and
            ($entraOperation.pkiId -or $entraOperation.pkiStatus -ceq 'created')
        )
    ) {
        throw 'The exact recorded lab PKI container no longer exists; refusing to replace it implicitly.'
    }
    $entraOperation.pkiStatus = 'planned'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
    $pki = Invoke-GraphJson -Method POST -Uri $pkiCollectionUri -Body @{
        displayName = $effectivePkiDisplayName
    }
    if (-not $pki.id) {
        throw 'PKI creation did not return an object ID; recovery state remains planned.'
    }
    $pkiCreated = $true
    $entraOperation.pkiCreated = $true
    $entraOperation.pkiId = $pki.id
    $entraOperation.pkiStatus = 'created'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
} else {
    $pki = $matchingPkis[0]
    if ($existingState -and (
        -not [bool]$existingState.pkiCreated -or
        $existingState.pkiId -ne $pki.id
    )) {
        throw (
            "PKI container '$effectivePkiDisplayName' is not bound as an object created by this solution; " +
            'refusing to adopt it.'
        )
    }
    if ($entraOperation -and (
        $entraOperation.pkiId -and
        $entraOperation.pkiId -ne $pki.id
    )) {
        throw 'The provisioning journal identifies a different PKI container.'
    }
    if ($entraOperation) {
        $entraOperation.pkiCreated = $true
        $entraOperation.pkiId = $pki.id
        $entraOperation.pkiStatus = 'created'
        Write-EntraStateAtomically `
            -Path $entraOperationStatePath `
            -State $entraOperation
        $pkiCreated = $true
    }
}

$caCollectionUri = "$pkiCollectionUri/$($pki.id)/certificateAuthorities"
$matchingCas = @(Get-ReconciledGraphMatches -Lookup {
    @(Get-GraphCollection -Uri $caCollectionUri) | Where-Object {
        $_.thumbprint.Replace(' ', '').ToUpperInvariant() -eq
            $pkiState.ca.thumbprint.Replace(' ', '').ToUpperInvariant()
    }
} -WaitForAppearance:(
    $entraOperation -and
    $entraOperation.caStatus -in @('planned', 'created')
))

if ($matchingCas.Count -gt 1) {
    throw 'More than one CA entry matched the generated root thumbprint.'
}

if ($matchingCas.Count -eq 0) {
    if (
        $existingState -or
        (
            $entraOperation -and
            ($entraOperation.caId -or $entraOperation.caStatus -ceq 'created')
        )
    ) {
        throw 'The exact recorded lab certificate authority no longer exists; refusing to replace it implicitly.'
    }
    $entraOperation.caStatus = 'planned'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
    $certificateBase64 = [Convert]::ToBase64String(
        [IO.File]::ReadAllBytes($pkiState.ca.certificatePath)
    )
    try {
        $ca = Invoke-GraphJson -Method POST -Uri $caCollectionUri -Body @{
            certificate = $certificateBase64
            certificateAuthorityType = 'root'
            certificateRevocationListUrl = $pkiState.crlUrl
            displayName = 'Entra CBA Playwright POC Root CA'
            expirationDateTime = [DateTime]::Parse($pkiState.ca.expirationDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            issuerSubjectKeyIdentifier = $pkiState.ca.subjectKeyIdentifier.ToLowerInvariant()
            isIssuerHintEnabled = $false
            thumbprint = $pkiState.ca.thumbprint.ToLowerInvariant()
        }
    }
    finally {
        $certificateBase64 = $null
    }
    if (-not $ca.id) {
        throw 'CA creation did not return an object ID; recovery state remains planned.'
    }
    $caCreated = $true
    $entraOperation.caCreated = $true
    $entraOperation.caId = $ca.id
    $entraOperation.caStatus = 'created'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
} else {
    $ca = $matchingCas[0]
    if ($existingState -and (
        -not [bool]$existingState.caCreated -or
        $existingState.caId -ne $ca.id
    )) {
        throw 'The matching certificate authority is not bound as an object created by this solution.'
    }
    if ($entraOperation -and (
        $entraOperation.caId -and
        $entraOperation.caId -ne $ca.id
    )) {
        throw 'The provisioning journal identifies a different certificate authority.'
    }
    if ($entraOperation) {
        $entraOperation.caCreated = $true
        $entraOperation.caId = $ca.id
        $entraOperation.caStatus = 'created'
        Write-EntraStateAtomically `
            -Path $entraOperationStatePath `
            -State $entraOperation
        $caCreated = $true
    }
}

$issuerSubjectKeyIdentifier = $ca.issuerSubjectKeyIdentifier
if (-not $issuerSubjectKeyIdentifier) {
    $ca = Invoke-MgGraphRequest -Method GET -Uri "$caCollectionUri/$($ca.id)"
    $issuerSubjectKeyIdentifier = $ca.issuerSubjectKeyIdentifier
}
if (-not $issuerSubjectKeyIdentifier) {
    throw 'The uploaded CA did not return an issuer subject key identifier.'
}

$scopedPolicyBody = $basePolicyBody.Clone()
$scopedPolicyBody.certificateAuthorityScopes = @(
    @{
        includeTargets = @(
            @{
                id = $group.id
                targetType = 'group'
            }
        )
        publicKeyInfrastructureIdentifier = $effectivePkiDisplayName
        subjectKeyIdentifier = $issuerSubjectKeyIdentifier
    }
)
if ($existingState) {
    if ($existingState.membershipAdded -and (
        $existingState.groupId -ne $group.id -or
        $existingState.testUserId -ne $user.id
    )) {
        throw 'Recorded membership ownership does not match the current group and user IDs.'
    }
    foreach ($ownedResource in @(
        @{
            IsOwned = [bool]$existingState.caCreated
            ExistingId = $existingState.caId
            CurrentId = $ca.id
            Label = 'certificate authority'
        },
        @{
            IsOwned = [bool]$existingState.pkiCreated
            ExistingId = $existingState.pkiId
            CurrentId = $pki.id
            Label = 'PKI container'
        },
        @{
            IsOwned = [bool]$existingState.groupCreated
            ExistingId = $existingState.groupId
            CurrentId = $group.id
            Label = 'group'
        },
        @{
            IsOwned = [bool]$existingState.testUserCreated
            ExistingId = $existingState.testUserId
            CurrentId = $user.id
            Label = 'test user'
        }
    )) {
        if ($ownedResource.IsOwned -and $ownedResource.ExistingId -ne $ownedResource.CurrentId) {
            throw "Recorded ownership for the $($ownedResource.Label) does not match the current object."
        }
    }
}
if ($entraOperation) {
    $entraOperation.policyStatus = 'planned'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
}
$policyMutationAttempted = $true
Invoke-GraphJson -Method PATCH -Uri $policyUri -Body $scopedPolicyBody | Out-Null
if ($entraOperation) {
    $entraOperation.policyStatus = 'applied'
    Write-EntraStateAtomically `
        -Path $entraOperationStatePath `
        -State $entraOperation
}

$verifiedPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
$verifiedPki = Invoke-MgGraphRequest -Method GET -Uri "$pkiCollectionUri/$($pki.id)"
$verifiedCas = @(Get-GraphCollection -Uri $caCollectionUri)

if (
    $verifiedPki.id -ne $pki.id -or
    $verifiedPki.displayName -cne $effectivePkiDisplayName
) {
    throw 'The PKI container read-back does not match the exact lab PKI.'
}
if ($verifiedCas.Count -ne 1) {
    throw 'The lab PKI must contain exactly one certificate authority.'
}
Assert-ExactLabX509Policy `
    -Policy $verifiedPolicy `
    -GroupId $group.id `
    -PolicyOid $pkiState.policyOid `
    -PkiDisplayName $effectivePkiDisplayName `
    -IssuerSubjectKeyIdentifier $issuerSubjectKeyIdentifier
Assert-ExactLabCertificateAuthority `
    -CertificateAuthority $verifiedCas[0] `
    -PkiState $pkiState `
    -ExpectedId $ca.id

$state = [ordered]@{
    caCreated = $caCreated -or [bool]$existingState.caCreated
    caId = $ca.id
    groupCreated = $groupCreated -or [bool]$existingState.groupCreated
    groupDisplayName = $GroupDisplayName
    groupId = $group.id
    membershipAdded = $membershipAdded -or [bool]$existingState.membershipAdded
    ownershipMarker = if ($entraOperation) {
        $entraOperation.ownershipMarker
    }
    elseif ($existingState.ContainsKey('ownershipMarker')) {
        $existingState.ownershipMarker
    }
    else {
        $null
    }
    policyOid = $pkiState.policyOid
    pkiCreated = $pkiCreated -or [bool]$existingState.pkiCreated
    pkiDisplayName = $effectivePkiDisplayName
    pkiId = $pki.id
    requestedPkiDisplayName = $PkiDisplayName
    schemaVersion = 2
    status = 'verified'
    testUserCreated = $userCreated -or [bool]$existingState.testUserCreated
    testUserId = $user.id
    testUserUpn = $TestUserUpn
    tenantId = $TenantId
    verifiedAt = (Get-Date).ToString('o')
}
Write-EntraStateAtomically -Path $entraStatePath -State $state
if ($entraOperation) {
    Remove-Item -LiteralPath $entraOperationStatePath -Force
}
} catch {
    $configurationError = $_
    $rollbackErrors = [Collections.Generic.List[string]]::new()
    if ($policyMutationAttempted) {
        try {
            Invoke-GraphJson -Method PATCH -Uri $policyUri -Body $policyRollbackBody | Out-Null
        } catch {
            $rollbackErrors.Add("X.509 policy restore failed: $($_.Exception.Message)")
        }
    }
    if ($entraOperation) {
        $detail = if ($rollbackErrors.Count -ne 0) {
            " Policy rollback also failed: $($rollbackErrors -join ' | ')."
        }
        else {
            ''
        }
        throw [InvalidOperationException]::new(
            (
                'Entra CBA configuration was interrupted; the exact recovery journal and ' +
                "created objects were retained for a safe rerun.$detail"
            ),
            $configurationError.Exception
        )
    }
    if ($caCreated -and $ca.id) {
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "$caCollectionUri/$($ca.id)"
        } catch {
            $rollbackErrors.Add("Certificate authority cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($pkiCreated -and $pki.id) {
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "$pkiCollectionUri/$($pki.id)"
        } catch {
            $rollbackErrors.Add("PKI cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($membershipAdded -and -not $groupCreated) {
        try {
            Invoke-MgGraphRequest `
                -Method DELETE `
                -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/$($user.id)/`$ref"
        } catch {
            $rollbackErrors.Add("Group membership cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($groupCreated -and $group.id) {
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)"
        } catch {
            $rollbackErrors.Add("Group cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($userCreated -and $user.id) {
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)"
        } catch {
            $rollbackErrors.Add("User cleanup failed: $($_.Exception.Message)")
        }
    }
    if ($rollbackErrors.Count -ne 0) {
        throw [InvalidOperationException]::new(
            "Entra CBA configuration failed and rollback was incomplete: $($rollbackErrors -join ' | ')",
            $configurationError.Exception
        )
    }
    throw $configurationError
}

Write-Host "Entra CBA is enabled only for group '$GroupDisplayName'."
Write-Host "Test user: $TestUserUpn"
Write-Host "PKI container: $PkiDisplayName"
Write-Warning 'Authentication-method policy changes can require up to one hour to propagate.'
}
finally {
    $entraOperationLock.Dispose()
}
