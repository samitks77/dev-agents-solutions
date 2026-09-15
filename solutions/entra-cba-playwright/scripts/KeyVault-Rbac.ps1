function Get-ApplicableRoleAssignments {
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$ResourceId
    )

    $resourceScope = $ResourceId.TrimEnd('/')
    $inheritedAssignments = @(
        az role assignment list `
            --assignee $PrincipalId `
            --scope $resourceScope `
            --include-groups `
            --include-inherited `
            --only-show-errors `
            --output json | ConvertFrom-Json
    )
    $allAssignments = @(
        az role assignment list `
            --assignee $PrincipalId `
            --all `
            --include-groups `
            --only-show-errors `
            --output json | ConvertFrom-Json
    )
    $descendantAssignments = @($allAssignments | Where-Object {
        ([string]$_.scope).StartsWith(
            "$resourceScope/",
            [StringComparison]::OrdinalIgnoreCase
        )
    })

    $assignmentsById = @{}
    foreach ($assignment in @($inheritedAssignments) + @($descendantAssignments)) {
        $assignmentsById[[string]$assignment.id] = $assignment
    }
    return @($assignmentsById.Values)
}

function Test-RoleDefinitionGrantsSecretMutation {
    param([Parameter(Mandatory)][object]$RoleDefinition)

    $mutationActions = @(
        'Microsoft.KeyVault/vaults/secrets/write',
        'Microsoft.KeyVault/vaults/secrets/setSecret/action',
        'Microsoft.KeyVault/vaults/secrets/delete',
        'Microsoft.KeyVault/vaults/secrets/recover/action',
        'Microsoft.KeyVault/vaults/secrets/backup/action',
        'Microsoft.KeyVault/vaults/secrets/restore/action',
        'Microsoft.KeyVault/vaults/secrets/purge/action'
    )
    foreach ($permission in @($RoleDefinition.permissions)) {
        foreach ($mutationAction in $mutationActions) {
            $allowed = @($permission.dataActions | Where-Object {
                $mutationAction -like [string]$_
            }).Count -gt 0
            $excluded = @($permission.notDataActions | Where-Object {
                $mutationAction -like [string]$_
            }).Count -gt 0
            if ($allowed -and -not $excluded) {
                return $true
            }
        }
    }
    return $false
}

function Get-KeyVaultSecretMutationAssignments {
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$VaultResourceId
    )

    $results = [Collections.Generic.List[object]]::new()
    $roleDefinitions = @{}
    foreach ($assignment in @(Get-ApplicableRoleAssignments `
        -PrincipalId $PrincipalId `
        -ResourceId $VaultResourceId)) {
        $roleDefinitionId = ([string]$assignment.roleDefinitionId).Split('/')[-1].ToLowerInvariant()
        if (-not $roleDefinitions.ContainsKey($roleDefinitionId)) {
            $matches = @(
                az role definition list `
                    --name $roleDefinitionId `
                    --output json | ConvertFrom-Json
            )
            if ($matches.Count -ne 1) {
                throw "Expected one Azure role definition for '$roleDefinitionId'."
            }
            $roleDefinitions[$roleDefinitionId] = $matches[0]
        }
        $roleDefinition = $roleDefinitions[$roleDefinitionId]
        if (Test-RoleDefinitionGrantsSecretMutation -RoleDefinition $roleDefinition) {
            $results.Add([pscustomobject]@{
                assignmentId = $assignment.id
                principalId = $assignment.principalId
                roleDefinitionId = $roleDefinitionId
                roleName = $roleDefinition.roleName
                scope = $assignment.scope
            })
        }
    }
    return $results.ToArray()
}
