function Test-EntraOperationHasNoMutationAttempt {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Operation,
        [Parameter(Mandatory)][string]$TenantId
    )

    $requiredProperties = @(
        'baselinePkiSha256'
        'baselinePolicySha256'
        'caCreated'
        'caId'
        'caStatus'
        'groupCreated'
        'groupDisplayName'
        'groupId'
        'groupStatus'
        'membershipAdded'
        'membershipStatus'
        'operationId'
        'ownershipMarker'
        'pkiCreated'
        'pkiId'
        'pkiObjectDisplayName'
        'pkiStatus'
        'policyOid'
        'policyStatus'
        'requestedPkiDisplayName'
        'schemaVersion'
        'status'
        'testUserCreated'
        'testUserDisplayName'
        'testUserId'
        'testUserStatus'
        'testUserUpn'
        'tenantId'
    )
    if (@($requiredProperties | Where-Object {
        -not $Operation.Contains($_)
    }).Count -ne 0) {
        return $false
    }

    $operationId = [guid]::Empty
    if (
        [int]$Operation.schemaVersion -ne 1 -or
        $Operation.status -cne 'provisioning' -or
        $Operation.tenantId -ine $TenantId -or
        -not [guid]::TryParseExact(
            [string]$Operation.operationId,
            'D',
            [ref]$operationId
        ) -or
        $Operation.ownershipMarker -cne
            "entra-cba-playwright/$($operationId.ToString('D'))" -or
        $Operation.pkiObjectDisplayName -cne (
            "$($Operation.requestedPkiDisplayName) [$($operationId.ToString('N'))]"
        ) -or
        [string]$Operation.baselinePkiSha256 -notmatch '^[a-f0-9]{64}$' -or
        [string]$Operation.baselinePolicySha256 -notmatch '^[a-f0-9]{64}$'
    ) {
        return $false
    }

    foreach ($statusProperty in @(
        'caStatus'
        'groupStatus'
        'membershipStatus'
        'pkiStatus'
        'policyStatus'
        'testUserStatus'
    )) {
        if ($Operation[$statusProperty] -cne 'pending') {
            return $false
        }
    }
    foreach ($createdProperty in @(
        'caCreated'
        'groupCreated'
        'membershipAdded'
        'pkiCreated'
        'testUserCreated'
    )) {
        if ([bool]$Operation[$createdProperty]) {
            return $false
        }
    }
    foreach ($idProperty in @('caId', 'groupId', 'pkiId', 'testUserId')) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Operation[$idProperty])) {
            return $false
        }
    }

    return $true
}
