[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [switch]$Connect
)

$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$entraOperationStatePath = Join-Path $stateDirectory 'entra-operation.json'
$pkiStatePath = Join-Path $stateDirectory 'pki.json'
$baselinePolicyPath = Join-Path $stateDirectory 'x509-policy-baseline.json'
$baselinePkiPath = Join-Path $stateDirectory 'pki-baseline.json'
$baselineContextPath = Join-Path $stateDirectory 'entra-baseline-context.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$conditionalAccessOperationPath = Join-Path `
    $stateDirectory `
    'conditional-access-operation.json'
$teardownStatePath = Join-Path $stateDirectory 'entra-teardown.json'
. (Join-Path $PSScriptRoot 'Teardown-State.ps1')
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$lifecycleLockPath = Join-Path $stateDirectory 'lab-lifecycle.lock'
try {
    $lifecycleLock = [IO.File]::Open(
        $lifecycleLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'Another bootstrap, FreshRun, or teardown owns the exclusive lab lifecycle lock.'
}
try {
if (Test-Path -LiteralPath $teardownStatePath) {
    $teardownState = Get-Content -LiteralPath $teardownStatePath -Raw | ConvertFrom-Json
    $teardownSchemaVersion = if (
        $teardownState.PSObject.Properties.Name -contains 'schemaVersion'
    ) {
        [int]$teardownState.schemaVersion
    }
    else {
        1
    }
    if (
        $teardownState.tenantId -eq $TenantId -and
        $teardownState.status -eq 'completed' -and
        $teardownSchemaVersion -eq 3
    ) {
        Write-Host "Entra CBA lab teardown already completed at $($teardownState.completedAt)."
        return
    }
    if ($teardownState.tenantId -eq $TenantId -and $teardownState.status -eq 'retiring') {
        throw 'Teardown state retirement is in progress; resume bootstrap with -RegeneratePki.'
    }
}
$isolationStatePath = Join-Path $stateDirectory 'conditional-access-isolation.json'
$isolationLockPath = Join-Path $stateDirectory 'conditional-access-isolation.lock'
try {
    $isolationLockStream = [IO.File]::Open(
        $isolationLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}
catch [IO.IOException] {
    throw 'A Conditional Access isolation transaction is active; teardown is blocked.'
}
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
    $isolationLockStream.Dispose()
    throw 'Another Conditional Access configuration owns the local lock.'
}
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
    $isolationLockStream.Dispose()
    $conditionalAccessOperationLock.Dispose()
    throw 'Another Entra configuration or teardown transaction owns the local lock.'
}
try {
if (
    (Test-Path -LiteralPath $conditionalAccessOperationPath -PathType Leaf) -and
    -not (Test-Path -LiteralPath $conditionalAccessStatePath -PathType Leaf)
) {
    throw (
        'Conditional Access creation recovery is incomplete. Rerun ' +
        'Configure-ConditionalAccess.ps1 before teardown.'
    )
}
if (Test-Path -LiteralPath $isolationStatePath -PathType Leaf) {
    $isolationState = Get-Content -LiteralPath $isolationStatePath -Raw |
        ConvertFrom-Json
    if (
        [int]$isolationState.schemaVersion -ne 3 -or
        $isolationState.status -cne 'restored' -or
        $isolationState.tenantId -ine $TenantId -or
        -not $isolationState.restoredAt
    ) {
        throw (
            'Conditional Access isolation is not restored for this tenant. ' +
            'Run the documented isolation recovery before teardown.'
        )
    }
}
$entraOwnershipStatePath = if (Test-Path -LiteralPath $entraStatePath -PathType Leaf) {
    $entraStatePath
}
elseif (Test-Path -LiteralPath $entraOperationStatePath -PathType Leaf) {
    $entraOperationStatePath
}
else {
    $entraStatePath
}
foreach ($requiredPath in @(
    $entraOwnershipStatePath,
    $pkiStatePath,
    $baselinePolicyPath,
    $baselinePkiPath
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required teardown state '$requiredPath' does not exist."
    }
}

$entra = Get-Content -LiteralPath $entraOwnershipStatePath -Raw |
    ConvertFrom-Json -AsHashtable
$usingProvisioningJournal = $entraOwnershipStatePath -ceq $entraOperationStatePath
if (
    -not $usingProvisioningJournal -and
    $entra.ContainsKey('status') -and
    $entra.status -notin @('verified', 'teardownPending')
) {
    throw 'Entra ownership state is not verified or in a recoverable teardown transition.'
}
if ($usingProvisioningJournal) {
    $operationId = [guid]::Empty
    if (
        [int]$entra.schemaVersion -ne 1 -or
        $entra.status -cne 'provisioning' -or
        -not [guid]::TryParseExact(
            [string]$entra.operationId,
            'D',
            [ref]$operationId
        ) -or
        $entra.ownershipMarker -cne
            "entra-cba-playwright/$($operationId.ToString('D'))" -or
        $entra.tenantId -ine $TenantId -or
        $entra.pkiObjectDisplayName -cne
            "$($entra.requestedPkiDisplayName) [$($operationId.ToString('N'))]"
    ) {
        throw 'Entra provisioning journal is not an exact teardown ownership record.'
    }
    $entra['pkiDisplayName'] = $entra.pkiObjectDisplayName
}
$pkiState = Get-Content -LiteralPath $pkiStatePath -Raw | ConvertFrom-Json
$baselinePolicy = Get-Content -LiteralPath $baselinePolicyPath -Raw | ConvertFrom-Json
Get-Content -LiteralPath $baselinePkiPath -Raw | ConvertFrom-Json | Out-Null
if (-not (Test-Path -LiteralPath $baselineContextPath -PathType Leaf)) {
    if (
        $entra.tenantId -ne $TenantId -or
        -not $entra.verifiedAt -or
        -not $entra.groupId -or
        -not $entra.testUserId -or
        -not $entra.pkiId -or
        -not $entra.caId
    ) {
        throw 'Legacy Entra state is incomplete and cannot be bound to its saved baseline.'
    }
    $legacyBaselineContext = [ordered]@{
        capturedAt = [DateTimeOffset]::UtcNow.ToString('o')
        migratedFromLegacyState = $true
        pkiSha256 = (
            Get-FileHash -LiteralPath $baselinePkiPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        policySha256 = (
            Get-FileHash -LiteralPath $baselinePolicyPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        tenantId = $entra.tenantId
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
    $entra.tenantId -ne $TenantId -or
    $baselineContext.tenantId -ne $TenantId -or
    $baselineContext.policySha256 -cne $policyBaselineHash -or
    $baselineContext.pkiSha256 -cne $pkiBaselineHash -or
    (
        $usingProvisioningJournal -and
        (
            $entra.baselinePolicySha256 -cne $policyBaselineHash -or
            $entra.baselinePkiSha256 -cne $pkiBaselineHash
        )
    )
) {
    throw 'Entra state or its saved baseline is not bound intact to the requested tenant.'
}
. (Join-Path $PSScriptRoot 'EntraCba-Policy.ps1')

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.39.0 -Force
$requiredScopes = @(
    'Group.ReadWrite.All',
    'Policy.ReadWrite.AuthenticationMethod',
    'Policy.ReadWrite.ConditionalAccess',
    'PublicKeyInfrastructure.ReadWrite.All',
    'User.ReadWrite.All'
)
$context = Get-MgContext
$missingScopes = @($requiredScopes | Where-Object { $_ -notin @($context.Scopes) })
if (-not $context -or $context.TenantId -ne $TenantId -or $missingScopes.Count -ne 0) {
    if (-not $Connect) {
        throw "No reusable Microsoft Graph context has all teardown scopes. Rerun with -Connect to authorize once."
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
    throw 'Microsoft Graph authorization for the exact teardown scopes is required.'
}

$policyUri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate'
$pkiCollectionUri = 'https://graph.microsoft.com/v1.0/directory/publicKeyInfrastructure/certificateBasedAuthConfigurations'

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

function Get-ReconciledTeardownMatches {
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
    throw 'Microsoft Graph object absence could not be proven after the teardown appearance window.'
}

function Assert-ReconciledGraphAbsence {
    param(
        [Parameter(Mandatory)][scriptblock]$Lookup,
        [Parameter(Mandatory)][string]$Label
    )

    $deadline = (Get-Date).AddMinutes(2)
    $consecutiveAbsenceChecks = 0
    do {
        $matches = @(& $Lookup)
        if ($matches.Count -eq 0) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge 3) {
                return
            }
        }
        else {
            $consecutiveAbsenceChecks = 0
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)

    throw "$Label was not verifiably absent after deletion."
}

$conditionalAccess = $null
$conditionalAccessPolicy = $null
if (Test-Path -LiteralPath $conditionalAccessStatePath) {
    $conditionalAccess = Get-Content -LiteralPath $conditionalAccessStatePath -Raw | ConvertFrom-Json
    if ($conditionalAccess.tenantId -ne $TenantId) {
        throw 'Conditional Access state belongs to a different tenant.'
    }
    $conditionalAccessPolicies = @(Get-GraphCollection `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')
    $policyMatches = @($conditionalAccessPolicies | Where-Object {
        $_.id -eq $conditionalAccess.policyId
    })
    if ($policyMatches.Count -gt 1) {
        throw 'More than one Conditional Access policy matched the recorded ID.'
    }
    if ($policyMatches.Count -eq 1) {
        $conditionalAccessPolicy = $policyMatches[0]
        if ($conditionalAccessPolicy.displayName -cne $conditionalAccess.policyDisplayName) {
            throw 'The recorded Conditional Access policy ID has an unexpected display name.'
        }
    }
}

$pkiMatches = @(Get-ReconciledTeardownMatches -Lookup {
    $livePkis = @(Get-GraphCollection -Uri $pkiCollectionUri)
    if ($entra.pkiId) {
        @($livePkis | Where-Object { $_.id -eq $entra.pkiId })
    }
    elseif ($usingProvisioningJournal) {
        @($livePkis | Where-Object {
            $_.displayName -ceq $entra.pkiDisplayName
        })
    }
} -WaitForAppearance:(
    $usingProvisioningJournal -and
    $entra.pkiStatus -in @('planned', 'created')
))
if ($usingProvisioningJournal -and -not $entra.pkiId) {
    if ($pkiMatches.Count -gt 1) {
        throw 'More than one PKI container matched the recovery-bound display name.'
    }
    if ($pkiMatches.Count -eq 1) {
        $entra['pkiId'] = $pkiMatches[0].id
        $entra['pkiCreated'] = $true
    }
}
if ($pkiMatches.Count -gt 1) {
    throw 'More than one PKI container matched the recorded ID.'
}
$pki = if ($pkiMatches.Count -eq 1) { $pkiMatches[0] } else { $null }
$certificateAuthority = $null
if ($pki) {
    if ($pki.displayName -cne $entra.pkiDisplayName) {
        throw 'The recorded PKI ID has an unexpected display name.'
    }
    $certificateAuthorities = @(Get-GraphCollection `
        -Uri "$pkiCollectionUri/$($pki.id)/certificateAuthorities")
    $caMatches = @(Get-ReconciledTeardownMatches -Lookup {
        $liveCas = @(Get-GraphCollection `
            -Uri "$pkiCollectionUri/$($pki.id)/certificateAuthorities")
        if ($entra.caId) {
            @($liveCas | Where-Object { $_.id -eq $entra.caId })
        }
        elseif ($usingProvisioningJournal) {
            @($liveCas | Where-Object {
                $_.thumbprint.Replace(' ', '').ToUpperInvariant() -eq
                    $pkiState.ca.thumbprint.Replace(' ', '').ToUpperInvariant()
            })
        }
    } -WaitForAppearance:(
        $usingProvisioningJournal -and
        $entra.caStatus -in @('planned', 'created')
    ))
    if ($caMatches.Count -gt 1) {
        throw 'More than one certificate authority matched the recorded ID.'
    }
    if ($caMatches.Count -eq 1) {
        $certificateAuthority = $caMatches[0]
        if ($usingProvisioningJournal -and -not $entra.caId) {
            $entra['caId'] = $certificateAuthority.id
            $entra['caCreated'] = $true
        }
        Assert-ExactLabCertificateAuthority `
            -CertificateAuthority $certificateAuthority `
            -PkiState $pkiState `
            -ExpectedId $entra.caId
    }
}

$expectedGroupName = if ($entra.groupDisplayName) {
    $entra.groupDisplayName
} else {
    'grp-entra-cba-playwright-poc'
}
$groups = @(Get-ReconciledTeardownMatches -Lookup {
    if ($entra.groupId) {
        $groupFilter = [Uri]::EscapeDataString("id eq '$($entra.groupId)'")
        @(Get-GraphCollection `
            -Uri (
                "https://graph.microsoft.com/v1.0/groups?`$filter=$groupFilter" +
                '&$select=id,displayName,description'
            ))
    }
    elseif ($usingProvisioningJournal) {
        $escapedGroupName = [Uri]::EscapeDataString(
            "displayName eq '$($entra.groupDisplayName.Replace("'", "''"))'"
        )
        @(Get-GraphCollection `
            -Uri (
                "https://graph.microsoft.com/v1.0/groups?`$filter=$escapedGroupName" +
                '&$select=id,displayName,description'
            )) | Where-Object {
                $_.description -ceq $entra.ownershipMarker
            }
    }
} -WaitForAppearance:(
    $usingProvisioningJournal -and
    $entra.groupStatus -in @('planned', 'created')
))
if ($usingProvisioningJournal -and -not $entra.groupId) {
    if ($groups.Count -gt 1) {
        throw 'More than one group matched the recovery ownership marker.'
    }
    if ($groups.Count -eq 1) {
        $entra['groupId'] = $groups[0].id
        $entra['groupCreated'] = $true
    }
}
$group = if ($groups.Count -eq 1) { $groups[0] } else { $null }
if (
    $groups.Count -gt 1 -or
    (
        $group -and
        (
            $group.displayName -cne $expectedGroupName -or
            (
                $entra.ownershipMarker -and
                $group.description -cne $entra.ownershipMarker
            )
        )
    )
) {
    throw 'The recorded group ID has an unexpected lab identity.'
}

$users = @(Get-ReconciledTeardownMatches -Lookup {
    if ($entra.testUserId) {
        $userFilter = [Uri]::EscapeDataString("id eq '$($entra.testUserId)'")
        @(Get-GraphCollection `
            -Uri (
                "https://graph.microsoft.com/v1.0/users?`$filter=$userFilter" +
                '&$select=id,userPrincipalName,employeeType'
            ))
    }
    elseif ($usingProvisioningJournal) {
        $escapedUpn = [Uri]::EscapeDataString(
            "userPrincipalName eq '$($entra.testUserUpn.Replace("'", "''"))'"
        )
        @(Get-GraphCollection `
            -Uri (
                "https://graph.microsoft.com/v1.0/users?`$filter=$escapedUpn" +
                '&$select=id,userPrincipalName,employeeType'
            )) | Where-Object {
                $_.employeeType -ceq $entra.ownershipMarker
            }
    }
} -WaitForAppearance:(
    $usingProvisioningJournal -and
    $entra.testUserStatus -in @('planned', 'created')
))
if ($usingProvisioningJournal -and -not $entra.testUserId) {
    if ($users.Count -gt 1) {
        throw 'More than one user matched the recovery ownership marker.'
    }
    if ($users.Count -eq 1) {
        $entra['testUserId'] = $users[0].id
        $entra['testUserCreated'] = $true
    }
}
$user = if ($users.Count -eq 1) { $users[0] } else { $null }
if (
    $users.Count -gt 1 -or
    (
        $user -and
        (
            $user.userPrincipalName -cne $entra.testUserUpn -or
            (
                $entra.ownershipMarker -and
                $user.employeeType -cne $entra.ownershipMarker
            )
        )
    )
) {
    throw 'The recorded user ID has an unexpected lab identity.'
}

$currentPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
$policyBody = ConvertTo-X509PolicyPatchBody -Policy $baselinePolicy
$currentPolicyBody = ConvertTo-X509PolicyPatchBody -Policy $currentPolicy
$policyAlreadyRestored = (
    ($currentPolicyBody | ConvertTo-Json -Depth 20 -Compress) -ceq
    ($policyBody | ConvertTo-Json -Depth 20 -Compress)
)
$currentPolicyMatchesLab = $false
$labPolicyValidationError = $null
if (-not $policyAlreadyRestored -and $group -and $pki -and $certificateAuthority) {
    try {
        Assert-ExactLabX509Policy `
            -Policy $currentPolicy `
            -GroupId $group.id `
            -PolicyOid $entra.policyOid `
            -PkiDisplayName $entra.pkiDisplayName `
            -IssuerSubjectKeyIdentifier $certificateAuthority.issuerSubjectKeyIdentifier
        $currentPolicyMatchesLab = $true
    }
    catch {
        $labPolicyValidationError = $_
    }
}
if (-not $policyAlreadyRestored -and -not $currentPolicyMatchesLab) {
    $detail = if ($labPolicyValidationError) {
        " $($labPolicyValidationError.Exception.Message)"
    }
    else {
        ''
    }
    throw (
        'The live X.509 policy matches neither the exact recorded lab policy nor its saved ' +
        "baseline; refusing teardown.$detail"
    )
}

if (-not $PSCmdlet.ShouldProcess(
    "tenant $TenantId",
    'restore the X.509 baseline and remove exact-ID lab Entra resources'
)) {
    return
}

if ($usingProvisioningJournal) {
    $entraState = [ordered]@{
        caCreated = [bool]$entra.caCreated
        caId = $entra.caId
        groupCreated = [bool]$entra.groupCreated
        groupDisplayName = $entra.groupDisplayName
        groupId = $entra.groupId
        membershipAdded = [bool]$entra.membershipAdded
        ownershipMarker = $entra.ownershipMarker
        policyOid = $entra.policyOid
        pkiCreated = [bool]$entra.pkiCreated
        pkiDisplayName = $entra.pkiDisplayName
        pkiId = $entra.pkiId
        requestedPkiDisplayName = $entra.requestedPkiDisplayName
        schemaVersion = 2
        status = 'teardownPending'
        testUserCreated = [bool]$entra.testUserCreated
        testUserId = $entra.testUserId
        testUserUpn = $entra.testUserUpn
        tenantId = $TenantId
        verifiedAt = $null
    }
    Write-EntraTeardownStateAtomically `
        -Path $entraStatePath `
        -State $entraState
    $entra = $entraState
}

if (-not $policyAlreadyRestored) {
    Invoke-MgGraphRequest `
        -Method PATCH `
        -Uri $policyUri `
        -Body ($policyBody | ConvertTo-Json -Depth 20) `
        -ContentType 'application/json' | Out-Null
}
$policyRestorationDeadline = (Get-Date).AddMinutes(2)
do {
    $restoredPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
    $restoredPolicyBody = ConvertTo-X509PolicyPatchBody -Policy $restoredPolicy
    if (
        ($restoredPolicyBody | ConvertTo-Json -Depth 20 -Compress) -ceq
        ($policyBody | ConvertTo-Json -Depth 20 -Compress)
    ) {
        break
    }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $policyRestorationDeadline)
if (
    ($restoredPolicyBody | ConvertTo-Json -Depth 20 -Compress) -cne
    ($policyBody | ConvertTo-Json -Depth 20 -Compress)
) {
    throw 'The X.509 authentication-method policy baseline was not restored.'
}

if ($conditionalAccessPolicy) {
    if ($conditionalAccess.policyCreated) {
        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($conditionalAccessPolicy.id)"
    } else {
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($conditionalAccessPolicy.id)" `
            -Body (@{ state = $conditionalAccess.policyOriginalState } | ConvertTo-Json) `
            -ContentType 'application/json' | Out-Null
    }
}
if ($conditionalAccess -and [bool]$conditionalAccess.policyCreated) {
    Assert-ReconciledGraphAbsence `
        -Label 'The exact lab Conditional Access policy' `
        -Lookup {
            @(Get-GraphCollection `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies') |
                Where-Object { $_.id -eq $conditionalAccess.policyId }
        }
}
elseif ($conditionalAccessPolicy) {
    $conditionalAccessRestorationDeadline = (Get-Date).AddMinutes(2)
    do {
        $restoredConditionalAccessPolicies = @(Get-GraphCollection `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')
        $restoredConditionalAccessMatches = @(
            $restoredConditionalAccessPolicies | Where-Object {
                $_.id -eq $conditionalAccess.policyId
            }
        )
        if (
            $restoredConditionalAccessMatches.Count -eq 1 -and
            $restoredConditionalAccessMatches[0].state -eq
                $conditionalAccess.policyOriginalState
        ) {
            break
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $conditionalAccessRestorationDeadline)
    if (
        $restoredConditionalAccessMatches.Count -ne 1 -or
        $restoredConditionalAccessMatches[0].state -ne
            $conditionalAccess.policyOriginalState
    ) {
        throw 'The pre-existing Conditional Access policy state was not restored.'
    }
}

if ($entra.caCreated -and $certificateAuthority) {
    Invoke-MgGraphRequest `
        -Method DELETE `
        -Uri "$pkiCollectionUri/$($entra.pkiId)/certificateAuthorities/$($entra.caId)"
}
if ($entra.caCreated -and $pki) {
    Assert-ReconciledGraphAbsence `
        -Label 'The exact lab certificate authority' `
        -Lookup {
            @(Get-GraphCollection `
                -Uri "$pkiCollectionUri/$($entra.pkiId)/certificateAuthorities") |
                Where-Object { $_.id -eq $entra.caId }
        }
}
if ($entra.pkiCreated -and $pki) {
    Invoke-MgGraphRequest -Method DELETE -Uri "$pkiCollectionUri/$($entra.pkiId)"
}
if ($entra.pkiCreated) {
    Assert-ReconciledGraphAbsence `
        -Label 'The exact lab PKI container' `
        -Lookup {
            @(Get-GraphCollection -Uri $pkiCollectionUri) |
                Where-Object { $_.id -eq $entra.pkiId }
        }
}
if ($entra.membershipAdded -and -not $entra.groupCreated -and $group -and $user) {
    $members = @(Get-GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id")
    if ($user.id -in @($members.id)) {
        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/$($user.id)/`$ref"
    }
    Assert-ReconciledGraphAbsence `
        -Label 'The exact lab group membership' `
        -Lookup {
            @(Get-GraphCollection `
                -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id") |
                Where-Object { $_.id -eq $user.id }
        }
}
if ($entra.groupCreated -and $group) {
    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)"
}
if ($entra.groupCreated) {
    $deletedGroupFilter = [Uri]::EscapeDataString("id eq '$($entra.groupId)'")
    Assert-ReconciledGraphAbsence `
        -Label 'The exact lab group' `
        -Lookup {
            @(Get-GraphCollection `
                -Uri (
                    "https://graph.microsoft.com/v1.0/groups?`$filter=$deletedGroupFilter" +
                    '&$select=id'
                )) |
                Where-Object { $_.id -eq $entra.groupId }
        }
}
if ($entra.testUserCreated -and $user) {
    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)"
}
if ($entra.testUserCreated) {
    $deletedUserFilter = [Uri]::EscapeDataString("id eq '$($entra.testUserId)'")
    Assert-ReconciledGraphAbsence `
        -Label 'The exact lab user' `
        -Lookup {
            @(Get-GraphCollection `
                -Uri (
                    "https://graph.microsoft.com/v1.0/users?`$filter=$deletedUserFilter" +
                    '&$select=id'
                )) |
                Where-Object { $_.id -eq $entra.testUserId }
        }
}

$teardownState = New-EntraTeardownStateRecord `
    -StateDirectory $stateDirectory `
    -TenantId $TenantId
Write-EntraTeardownStateAtomically `
    -Path $teardownStatePath `
    -State $teardownState
Write-Host 'The X.509 policy baseline was restored and exact-ID lab Entra resources were removed.'
}
finally {
    $isolationLockStream.Dispose()
    $conditionalAccessOperationLock.Dispose()
    $entraOperationLock.Dispose()
}
}
finally {
    $lifecycleLock.Dispose()
}
