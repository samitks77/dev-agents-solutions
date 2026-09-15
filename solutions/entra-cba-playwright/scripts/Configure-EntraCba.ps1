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
$entraStatePath = Join-Path $stateDirectory 'entra.json'
. (Join-Path $PSScriptRoot 'EntraCba-Policy.ps1')

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

$policyUri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate'
$pkiCollectionUri = 'https://graph.microsoft.com/v1.0/directory/publicKeyInfrastructure/certificateBasedAuthConfigurations'

$existingPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
$existingPkis = Invoke-MgGraphRequest -Method GET -Uri $pkiCollectionUri

if (-not (Test-Path $baselinePolicyPath)) {
    $existingPolicy | ConvertTo-Json -Depth 20 | Set-Content -Path $baselinePolicyPath -Encoding utf8NoBOM
}
if (-not (Test-Path $baselinePkiPath)) {
    $existingPkis | ConvertTo-Json -Depth 20 | Set-Content -Path $baselinePkiPath -Encoding utf8NoBOM
}

$existingState = if (Test-Path $entraStatePath) {
    Get-Content $entraStatePath -Raw | ConvertFrom-Json
} else {
    $null
}

$escapedGroupName = [Uri]::EscapeDataString("displayName eq '$($GroupDisplayName.Replace("'", "''"))'")
$groupQueryUri = "https://graph.microsoft.com/v1.0/groups?`$filter=$escapedGroupName&`$select=id,displayName,securityEnabled"
$groups = @((
    Invoke-MgGraphRequest -Method GET -Uri $groupQueryUri
).value)
if ($groups.Count -gt 1) {
    throw "More than one group matched '$GroupDisplayName'."
}

$knownLabGroupId = if ($existingState) {
    $existingState.groupId
} elseif ($groups.Count -eq 1) {
    $groups[0].id
} else {
    $null
}

$foreignTargets = @($existingPolicy.includeTargets) | Where-Object {
    -not $knownLabGroupId -or $_.id -ne $knownLabGroupId
}
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

function Get-GraphCollection {
    param(
        [Parameter(Mandatory)][string]$Uri
    )

    $items = [Collections.Generic.List[object]]::new()
    while ($Uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $Uri
        foreach ($item in @($response.value)) {
            $items.Add($item)
        }
        $Uri = $response.'@odata.nextLink'
    }
    return $items.ToArray()
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

$userCreated = $false
$groupCreated = $false
$membershipAdded = $false
$pkiCreated = $false
$caCreated = $false
$policyMutationAttempted = $false
$policyRollbackBody = ConvertTo-X509PolicyPatchBody -Policy $existingPolicy
$teardownStatePath = Join-Path $stateDirectory 'entra-teardown.json'
Remove-Item -LiteralPath $teardownStatePath -Force -ErrorAction SilentlyContinue

try {
$escapedUpn = [Uri]::EscapeDataString("userPrincipalName eq '$($TestUserUpn.Replace("'", "''"))'")
$userQueryUri = "https://graph.microsoft.com/v1.0/users?`$filter=$escapedUpn&`$select=id,displayName,userPrincipalName,accountEnabled"
$users = @((
    Invoke-MgGraphRequest -Method GET -Uri $userQueryUri
).value)

if ($users.Count -gt 1) {
    throw "More than one user matched '$TestUserUpn'."
}

if ($users.Count -eq 0) {
    $password = New-RandomPassword
    try {
        $user = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Body @{
            accountEnabled = $true
            displayName = $TestUserDisplayName
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
    $userCreated = $true
} else {
    $user = $users[0]
}

if ($groups.Count -eq 0) {
    $group = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/v1.0/groups' -Body @{
        displayName = $GroupDisplayName
        groupTypes = @()
        mailEnabled = $false
        mailNickname = 'grp-entra-cba-playwright-poc'
        securityEnabled = $true
    }
    $groupCreated = $true
} else {
    $group = $groups[0]
    if (-not $group.securityEnabled) {
        throw "Existing group '$GroupDisplayName' is not security-enabled."
    }
}

$membersUri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id&`$top=999"
$members = @(Get-GraphCollection -Uri $membersUri)
$foreignMembers = @($members | Where-Object { $_.id -ne $user.id })
if ($foreignMembers.Count -ne 0) {
    throw "Group '$GroupDisplayName' contains $($foreignMembers.Count) non-lab member(s); refusing to expand CBA scope."
}
if ($user.id -notin $members.id) {
    Invoke-GraphJson `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/`$ref" `
        -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)" } | Out-Null
    $membershipAdded = $true
}
$verifiedMembers = @(Get-GraphCollection -Uri $membersUri)
if ($verifiedMembers.Count -ne 1 -or $verifiedMembers[0].id -ne $user.id) {
    throw "Group '$GroupDisplayName' must contain only the dedicated test user."
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

$matchingPkis = @($existingPkis.value) | Where-Object { $_.displayName -eq $PkiDisplayName }
if ($matchingPkis.Count -gt 1) {
    $baselinePkis = Get-Content $baselinePkiPath -Raw | ConvertFrom-Json
    if (@($baselinePkis.value).Count -ne 0) {
        throw "Multiple PKI containers are named '$PkiDisplayName', and the saved baseline was not empty."
    }

    $pkiCandidates = foreach ($candidate in $matchingPkis) {
        $candidateCaUri = "$pkiCollectionUri/$($candidate.id)/certificateAuthorities"
        $candidateCas = @((
            Invoke-MgGraphRequest -Method GET -Uri $candidateCaUri
        ).value)
        [pscustomobject]@{
            pki = $candidate
            certificateAuthorities = $candidateCas
        }
    }

    $nonEmptyCandidates = @($pkiCandidates | Where-Object { $_.certificateAuthorities.Count -gt 0 })
    if ($nonEmptyCandidates.Count -gt 1) {
        throw "Multiple non-empty PKI containers are named '$PkiDisplayName'; manual review is required."
    }

    $selectedCandidate = if ($nonEmptyCandidates.Count -eq 1) {
        $nonEmptyCandidates[0]
    } else {
        $pkiCandidates | Select-Object -First 1
    }

    foreach ($duplicate in $pkiCandidates | Where-Object { $_.pki.id -ne $selectedCandidate.pki.id }) {
        if ($duplicate.certificateAuthorities.Count -ne 0) {
            throw 'Refusing to delete a duplicate PKI container that contains a certificate authority.'
        }
        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri "$pkiCollectionUri/$($duplicate.pki.id)"
    }

    $matchingPkis = @($selectedCandidate.pki)
}

if ($matchingPkis.Count -eq 0) {
    $pki = Invoke-GraphJson -Method POST -Uri $pkiCollectionUri -Body @{
        displayName = $PkiDisplayName
    }
    $pkiCreated = $true
} else {
    $pki = $matchingPkis[0]
}

$caCollectionUri = "$pkiCollectionUri/$($pki.id)/certificateAuthorities"
$existingCas = @((
    Invoke-MgGraphRequest -Method GET -Uri $caCollectionUri
).value)
$matchingCas = $existingCas | Where-Object {
    $_.thumbprint.Replace(' ', '').ToUpperInvariant() -eq $pkiState.ca.thumbprint.Replace(' ', '').ToUpperInvariant()
}

if ($matchingCas.Count -gt 1) {
    throw 'More than one CA entry matched the generated root thumbprint.'
}

if ($matchingCas.Count -eq 0) {
    $certificateBase64 = [Convert]::ToBase64String(
        [IO.File]::ReadAllBytes($pkiState.ca.certificatePath)
    )
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
    $certificateBase64 = $null
    $caCreated = $true
} else {
    $ca = $matchingCas[0]
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
        publicKeyInfrastructureIdentifier = $PkiDisplayName
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
$policyMutationAttempted = $true
Invoke-GraphJson -Method PATCH -Uri $policyUri -Body $scopedPolicyBody | Out-Null

$verifiedPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri
$verifiedPki = Invoke-MgGraphRequest -Method GET -Uri "$pkiCollectionUri/$($pki.id)"
$verifiedCas = Invoke-MgGraphRequest -Method GET -Uri $caCollectionUri

if ($verifiedPki.id -ne $pki.id -or $verifiedPki.displayName -cne $PkiDisplayName) {
    throw 'The PKI container read-back does not match the exact lab PKI.'
}
if (@($verifiedCas.value).Count -ne 1) {
    throw 'The lab PKI must contain exactly one certificate authority.'
}
Assert-ExactLabX509Policy `
    -Policy $verifiedPolicy `
    -GroupId $group.id `
    -PolicyOid $pkiState.policyOid `
    -PkiDisplayName $PkiDisplayName `
    -IssuerSubjectKeyIdentifier $issuerSubjectKeyIdentifier
Assert-ExactLabCertificateAuthority `
    -CertificateAuthority $verifiedCas.value[0] `
    -PkiState $pkiState `
    -ExpectedId $ca.id

$state = [ordered]@{
    caCreated = $caCreated -or [bool]$existingState.caCreated
    caId = $ca.id
    groupCreated = $groupCreated -or [bool]$existingState.groupCreated
    groupDisplayName = $GroupDisplayName
    groupId = $group.id
    membershipAdded = $membershipAdded -or [bool]$existingState.membershipAdded
    policyOid = $pkiState.policyOid
    pkiCreated = $pkiCreated -or [bool]$existingState.pkiCreated
    pkiDisplayName = $PkiDisplayName
    pkiId = $pki.id
    testUserCreated = $userCreated -or [bool]$existingState.testUserCreated
    testUserId = $user.id
    testUserUpn = $TestUserUpn
    tenantId = $TenantId
    verifiedAt = (Get-Date).ToString('o')
}
$state | ConvertTo-Json -Depth 8 | Set-Content -Path $entraStatePath -Encoding utf8NoBOM
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
