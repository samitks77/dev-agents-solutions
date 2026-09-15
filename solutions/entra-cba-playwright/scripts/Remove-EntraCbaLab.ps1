[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [switch]$Connect
)

$ErrorActionPreference = 'Stop'

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$entraStatePath = Join-Path $stateDirectory 'entra.json'
$pkiStatePath = Join-Path $stateDirectory 'pki.json'
$baselinePolicyPath = Join-Path $stateDirectory 'x509-policy-baseline.json'
$conditionalAccessStatePath = Join-Path $stateDirectory 'conditional-access.json'
$teardownStatePath = Join-Path $stateDirectory 'entra-teardown.json'
if (Test-Path -LiteralPath $teardownStatePath) {
    $teardownState = Get-Content -LiteralPath $teardownStatePath -Raw | ConvertFrom-Json
    if ($teardownState.tenantId -eq $TenantId -and $teardownState.status -eq 'completed') {
        Write-Host "Entra CBA lab teardown already completed at $($teardownState.completedAt)."
        return
    }
}
foreach ($requiredPath in @($entraStatePath, $pkiStatePath, $baselinePolicyPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required teardown state '$requiredPath' does not exist."
    }
}

$entra = Get-Content -LiteralPath $entraStatePath -Raw | ConvertFrom-Json
$pkiState = Get-Content -LiteralPath $pkiStatePath -Raw | ConvertFrom-Json
$baselinePolicy = Get-Content -LiteralPath $baselinePolicyPath -Raw | ConvertFrom-Json
if ($entra.tenantId -ne $TenantId) {
    throw 'Entra state belongs to a different tenant.'
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
        $Uri = $response.'@odata.nextLink'
    }
    return $items.ToArray()
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

$pkiMatches = @(Get-GraphCollection -Uri $pkiCollectionUri) | Where-Object {
    $_.id -eq $entra.pkiId
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
    $caMatches = @($certificateAuthorities | Where-Object { $_.id -eq $entra.caId })
    if ($caMatches.Count -gt 1) {
        throw 'More than one certificate authority matched the recorded ID.'
    }
    if ($caMatches.Count -eq 1) {
        $certificateAuthority = $caMatches[0]
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
$groupFilter = [Uri]::EscapeDataString("id eq '$($entra.groupId)'")
$groups = @(Get-GraphCollection `
    -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$groupFilter&`$select=id,displayName")
$group = if ($groups.Count -eq 1) { $groups[0] } else { $null }
if ($groups.Count -gt 1 -or ($group -and $group.displayName -cne $expectedGroupName)) {
    throw 'The recorded group ID has an unexpected lab identity.'
}

$userFilter = [Uri]::EscapeDataString("id eq '$($entra.testUserId)'")
$users = @(Get-GraphCollection `
    -Uri "https://graph.microsoft.com/v1.0/users?`$filter=$userFilter&`$select=id,userPrincipalName")
$user = if ($users.Count -eq 1) { $users[0] } else { $null }
if ($users.Count -gt 1 -or ($user -and $user.userPrincipalName -cne $entra.testUserUpn)) {
    throw 'The recorded user ID has an unexpected lab identity.'
}

if (-not $PSCmdlet.ShouldProcess(
    "tenant $TenantId",
    'restore the X.509 baseline and remove exact-ID lab Entra resources'
)) {
    return
}

$policyBody = ConvertTo-X509PolicyPatchBody -Policy $baselinePolicy
Invoke-MgGraphRequest `
    -Method PATCH `
    -Uri $policyUri `
    -Body ($policyBody | ConvertTo-Json -Depth 20) `
    -ContentType 'application/json' | Out-Null

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

if ($entra.caCreated -and $certificateAuthority) {
    Invoke-MgGraphRequest `
        -Method DELETE `
        -Uri "$pkiCollectionUri/$($entra.pkiId)/certificateAuthorities/$($entra.caId)"
}
if ($entra.pkiCreated -and $pki) {
    Invoke-MgGraphRequest -Method DELETE -Uri "$pkiCollectionUri/$($entra.pkiId)"
}
if ($entra.membershipAdded -and -not $entra.groupCreated -and $group -and $user) {
    $members = @(Get-GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id")
    if ($user.id -in @($members.id)) {
        Invoke-MgGraphRequest `
            -Method DELETE `
            -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members/$($user.id)/`$ref"
    }
}
if ($entra.groupCreated -and $group) {
    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)"
}
if ($entra.testUserCreated -and $user) {
    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)"
}

$teardownState = [ordered]@{
    completedAt = (Get-Date).ToString('o')
    status = 'completed'
    tenantId = $TenantId
}
$teardownState | ConvertTo-Json | Set-Content -LiteralPath $teardownStatePath -Encoding utf8NoBOM
Write-Host 'The X.509 policy baseline was restored and exact-ID lab Entra resources were removed.'
