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
        'Microsoft.KeyVault/vaults/secrets/update/action',
        'Microsoft.KeyVault/vaults/secrets/backup/action',
        'Microsoft.KeyVault/vaults/secrets/restore/action',
        'Microsoft.KeyVault/vaults/secrets/purge/action'
    )
    foreach ($permission in @($RoleDefinition.permissions)) {
        foreach ($mutationAction in $mutationActions) {
            $dataActionAllowed = @($permission.dataActions | Where-Object {
                $mutationAction -like [string]$_
            }).Count -gt 0
            $dataActionExcluded = @($permission.notDataActions | Where-Object {
                $mutationAction -like [string]$_
            }).Count -gt 0
            $controlActionAllowed = @($permission.actions | Where-Object {
                $mutationAction -like [string]$_
            }).Count -gt 0
            $controlActionExcluded = @($permission.notActions | Where-Object {
                $mutationAction -like [string]$_
            }).Count -gt 0
            if (
                ($dataActionAllowed -and -not $dataActionExcluded) -or
                ($controlActionAllowed -and -not $controlActionExcluded)
            ) {
                return $true
            }
        }
        foreach ($escalationAction in @(
            'Microsoft.Authorization/elevateAccess/action'
            'Microsoft.Authorization/roleAssignments/write'
            'Microsoft.Authorization/roleDefinitions/write'
            'Microsoft.KeyVault/vaults/accessPolicies/write'
            'Microsoft.KeyVault/vaults/write'
        )) {
            $allowed = @($permission.actions | Where-Object {
                $escalationAction -like [string]$_
            }).Count -gt 0
            $excluded = @($permission.notActions | Where-Object {
                $escalationAction -like [string]$_
            }).Count -gt 0
            if ($allowed -and -not $excluded) {
                return $true
            }
        }
    }
    return $false
}

function Get-KeyVaultSecretMutationCapabilityAssignments {
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
        # Conditional control-plane grants remain unsafe unless this verifier can prove them harmless.
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

function Get-RecordedPublisherAssignmentId {
    param(
        [Parameter(Mandatory)][string]$OperationStatePath,
        [Parameter(Mandatory)][string]$PublisherPrincipalId,
        [Parameter(Mandatory)][string]$VaultResourceId
    )

    if (-not (Test-Path -LiteralPath $OperationStatePath -PathType Leaf)) {
        return $null
    }
    $operation = Get-Content -LiteralPath $OperationStatePath -Raw | ConvertFrom-Json
    $assignmentGuid = [guid]::Empty
    $expectedRoleDefinitionId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    $expectedAssignmentId = (
        "$($VaultResourceId.TrimEnd('/'))/providers/Microsoft.Authorization/roleAssignments/" +
        [string]$operation.assignmentName
    )
    if (
        [int]$operation.schemaVersion -ne 1 -or
        $operation.status -notin @('planned', 'created', 'cleanupPending') -or
        $operation.roleDefinitionId -cne $expectedRoleDefinitionId -or
        -not [guid]::TryParseExact(
            [string]$operation.assignmentName,
            'D',
            [ref]$assignmentGuid
        ) -or
        -not [string]::Equals(
            [string]$operation.publisherPrincipalId,
            $PublisherPrincipalId,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string]$operation.vaultId,
            $VaultResourceId,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string]$operation.assignmentId,
            $expectedAssignmentId,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw 'Publisher operation state is not bound to the exact lab identity, vault, and role ID.'
    }
    return [string]$operation.assignmentId
}

function Remove-ExactPublisherAssignment {
    param(
        [Parameter(Mandatory)][string]$AssignmentId,
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$VaultResourceId,
        [Parameter(Mandatory)][string]$RoleDefinitionId,
        [switch]$RequireAppearanceWindow,
        [switch]$ConfirmedLiveAssignment
    )

    if ($RequireAppearanceWindow -and $ConfirmedLiveAssignment) {
        throw 'Select either uncertain recovery or confirmed live-assignment cleanup, not both.'
    }
    $appearanceDeadline = (Get-Date).AddMinutes(10)
    $cleanupDeadline = $appearanceDeadline.AddMinutes(2)
    $lastRevocationError = $null
    $assignmentObserved = [bool]$ConfirmedLiveAssignment
    $deleteByIdPending = [bool]$ConfirmedLiveAssignment
    $consecutiveAbsenceChecks = 0
    do {
        $targetAssignments = @()
        try {
            if ($deleteByIdPending) {
                az role assignment delete --ids $AssignmentId --output none
                $deleteByIdPending = $false
            }
            $scopeAssignments = @(
                az role assignment list `
                    --scope $VaultResourceId `
                    --include-inherited `
                    --output json | ConvertFrom-Json
            )
            $matchingIdAssignments = @($scopeAssignments | Where-Object {
                $_.id -ieq $AssignmentId
            })
            $invalidMatchingIdAssignments = @($matchingIdAssignments | Where-Object {
                $_.principalId -ine $PrincipalId -or
                $_.scope -ine $VaultResourceId -or
                (Split-Path -Leaf $_.roleDefinitionId) -ine $RoleDefinitionId
            })
            if ($invalidMatchingIdAssignments.Count -ne 0) {
                throw 'The recorded assignment ID exists with unexpected principal, scope, or role.'
            }
            $targetAssignments = @($matchingIdAssignments)
            if ($targetAssignments.Count -gt 1) {
                throw 'Azure returned duplicate exact publisher role assignments.'
            }
            if ($targetAssignments.Count -eq 1) {
                $assignmentObserved = $true
                $consecutiveAbsenceChecks = 0
                az role assignment delete --ids $AssignmentId --output none
            }
            elseif (
                $assignmentObserved -or
                -not $RequireAppearanceWindow -or
                (Get-Date) -ge $appearanceDeadline
            ) {
                $consecutiveAbsenceChecks++
            }
            $lastRevocationError = $null
        }
        catch {
            $lastRevocationError = $_
            $consecutiveAbsenceChecks = 0
        }
        if ($consecutiveAbsenceChecks -lt 3 -or $lastRevocationError) {
            Start-Sleep -Seconds 5
        }
    } while (
        ($consecutiveAbsenceChecks -lt 3 -or $lastRevocationError) -and
        (Get-Date) -lt $cleanupDeadline
    )

    $scopeAssignments = @(
        az role assignment list `
            --scope $VaultResourceId `
            --include-inherited `
            --output json | ConvertFrom-Json
    )
    $remainingTargetAssignments = @($scopeAssignments | Where-Object {
        $_.id -ieq $AssignmentId
    })
    $invalidRemainingTargetAssignments = @($remainingTargetAssignments | Where-Object {
        $_.principalId -ine $PrincipalId -or
        $_.scope -ine $VaultResourceId -or
        (Split-Path -Leaf $_.roleDefinitionId) -ine $RoleDefinitionId
    })
    if ($invalidRemainingTargetAssignments.Count -ne 0) {
        throw 'The recorded assignment ID has unexpected live properties and was not deleted.'
    }
    if ($remainingTargetAssignments.Count -ne 0) {
        throw 'The exact recorded publisher role assignment was not revoked.'
    }
    if (
        $assignmentObserved -or
        -not $RequireAppearanceWindow -or
        (Get-Date) -ge $appearanceDeadline
    ) {
        $consecutiveAbsenceChecks++
    }
    if ($consecutiveAbsenceChecks -lt 3) {
        throw 'The exact assignment was not verifiably absent across the bounded consistency window.'
    }
    $publisherMutationAssignments = @(Get-KeyVaultSecretMutationCapabilityAssignments `
        -PrincipalId $PrincipalId `
        -VaultResourceId $VaultResourceId)
    if ($publisherMutationAssignments.Count -ne 0) {
        $roleSummary = $publisherMutationAssignments | ForEach-Object {
            "'$($_.roleName)' at '$($_.scope)'"
        }
        throw (
            'The publisher identity still has direct or self-elevatable secret-mutation ' +
            "access after exact-assignment revocation: $($roleSummary -join ', ')."
        )
    }
}

function Remove-ExactPublisherContainerGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$OperationId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [switch]$RequireAppearanceWindow
    )

    $appearanceDeadline = (Get-Date).AddMinutes(10)
    $cleanupDeadline = $appearanceDeadline.AddMinutes(2)
    $containerObserved = $false
    $consecutiveAbsenceChecks = 0
    do {
        $matchingContainers = @(
            @(
                az container list `
                    --resource-group $ResourceGroup `
                    --output json | ConvertFrom-Json
            ) | Where-Object {
                $_.name -ceq $Name
            }
        )
        if ($matchingContainers.Count -gt 1) {
            throw "Azure returned duplicate publisher container name '$Name'."
        }
        if ($matchingContainers.Count -eq 1) {
            $containerObserved = $true
            $container = $matchingContainers[0]
            if (
                $container.tags.component -cne 'credential-publisher' -or
                $container.tags.managedBy -cne 'script' -or
                $container.tags.workload -cne 'entra-cba-playwright' -or
                $container.tags.operationId -cne $OperationId
            ) {
                throw (
                    "Publisher container '$Name' is not owned by operation '$OperationId' " +
                    'and was not deleted.'
                )
            }
            $consecutiveAbsenceChecks = 0
            az container delete `
                --name $Name `
                --resource-group $ResourceGroup `
                --yes `
                --output none
        }
        elseif (
            $containerObserved -or
            -not $RequireAppearanceWindow -or
            (Get-Date) -ge $appearanceDeadline
        ) {
            $consecutiveAbsenceChecks++
        }
        if ($consecutiveAbsenceChecks -lt 3) {
            Start-Sleep -Seconds 5
        }
    } while (
        $consecutiveAbsenceChecks -lt 3 -and
        (Get-Date) -lt $cleanupDeadline
    )

    if ($consecutiveAbsenceChecks -lt 3) {
        throw "Publisher container '$Name' was not verifiably absent after deletion."
    }
}

function Assert-LabVaultRbac {
    <#
    .SYNOPSIS
    Verifies that the lab Key Vault grants the GitHub workload identity exactly one direct
    Key Vault Secrets User assignment and no Key Vault Secrets Officer or other
    secret-mutation assignment.

    .DESCRIPTION
    Shared by script and portal deployment paths. Read-only discovery may allow only a direct
    Secrets Officer assignment held by one of the two exact lab identities so consented recovery
    remains reachable. Repair deletes only those assignments; unrelated assignments always fail.
    #>
    param(
        [Parameter(Mandatory)][object]$Outputs,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [switch]$RepairLegacyAssignments,
        [switch]$AllowRepairableLabAssignments,
        [string]$RepairableAssignmentId
    )
    if ($RepairLegacyAssignments -and $AllowRepairableLabAssignments) {
        throw 'Select repair or read-only allowance for exact lab assignments, not both.'
    }

    $vaultName = $Outputs.runnerVaultName.value
    $workloadPrincipalId = $Outputs.workloadPrincipalId.value
    $publisherPrincipalId = $Outputs.publisherPrincipalId.value
    if (-not $vaultName -or -not $workloadPrincipalId -or -not $publisherPrincipalId) {
        throw 'Infrastructure outputs do not identify the runner vault and both lab principals.'
    }
    $vault = az keyvault show `
        --name $vaultName `
        --resource-group $ResourceGroup `
        --output json | ConvertFrom-Json
    if ($vault.properties.enableRbacAuthorization -ne $true) {
        throw "Key Vault '$vaultName' must use Azure RBAC authorization, not access policies."
    }

    # Public Azure built-in Key Vault Secrets Officer role definition ID.
    $secretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' # gitleaks:allow - Public Azure role ID.
    $directOfficerAssignments = @(
        @(
            az role assignment list `
                --scope $vault.id `
                --role $secretsOfficerRoleId `
                --output json | ConvertFrom-Json
        ) | Where-Object { $_.scope -eq $vault.id }
    )
    $repairableAssignments = @($directOfficerAssignments | Where-Object {
        $_.principalId -eq $publisherPrincipalId -and
        $RepairableAssignmentId -and
        $_.id -ieq $RepairableAssignmentId
    })
    $unrelatedOfficerAssignments = @($directOfficerAssignments | Where-Object {
        $_.id -notin @($repairableAssignments.id)
    })
    if ($unrelatedOfficerAssignments.Count -ne 0) {
        throw (
            'The lab vault has a direct Key Vault Secrets Officer assignment for a principal ' +
            'or assignment ID outside the exact recorded recovery operation. No unrelated ' +
            'assignment was modified.'
        )
    }
    if ($RepairLegacyAssignments) {
        foreach ($assignment in $repairableAssignments) {
            az role assignment delete --ids $assignment.id --output none
        }
        $revocationDeadline = (Get-Date).AddMinutes(2)
        do {
            $directOfficerAssignments = @(
                @(
                    az role assignment list `
                        --scope $vault.id `
                        --role $secretsOfficerRoleId `
                        --output json | ConvertFrom-Json
                ) | Where-Object { $_.scope -eq $vault.id }
            )
            $remainingRepairableAssignments = @($directOfficerAssignments | Where-Object {
                $_.id -ieq $RepairableAssignmentId
            })
            $appearedUnexpectedAssignments = @($directOfficerAssignments | Where-Object {
                $_.id -ine $RepairableAssignmentId
            })
            if ($appearedUnexpectedAssignments.Count -ne 0) {
                throw (
                    'An unrecorded direct Secrets Officer assignment appeared during repair. ' +
                    'No unrelated assignment was modified.'
                )
            }
            if ($remainingRepairableAssignments.Count -ne 0) {
                Start-Sleep -Seconds 5
            }
        } while (
            $remainingRepairableAssignments.Count -ne 0 -and
            (Get-Date) -lt $revocationDeadline
        )
        $repairableAssignments = $remainingRepairableAssignments
    }
    if ($repairableAssignments.Count -ne 0 -and -not $AllowRepairableLabAssignments) {
        throw (
            'An exact lab identity retains a direct Key Vault Secrets Officer assignment.'
        )
    }

    foreach ($principalContract in @(
        @{ label = 'GitHub workload identity'; principalId = $workloadPrincipalId },
        @{ label = 'publisher identity'; principalId = $publisherPrincipalId }
    )) {
        $mutationAssignments = @(Get-KeyVaultSecretMutationCapabilityAssignments `
            -PrincipalId $principalContract.principalId `
            -VaultResourceId $vault.id)
        $allowedRepairAssignmentIds = if ($AllowRepairableLabAssignments) {
            if ($principalContract.principalId -eq $publisherPrincipalId) {
                @($repairableAssignments.id)
            }
            else {
                @()
            }
        }
        else {
            @()
        }
        $unexpectedMutationAssignments = @($mutationAssignments | Where-Object {
            $_.assignmentId -notin $allowedRepairAssignmentIds
        })
        if ($unexpectedMutationAssignments.Count -ne 0) {
            $roleSummary = $unexpectedMutationAssignments | ForEach-Object {
                "'$($_.roleName)' at '$($_.scope)'"
            }
            throw (
                "The $($principalContract.label) has direct or self-elevatable secret " +
                'mutation capability through ' +
                "$($roleSummary -join ', ')."
            )
        }
    }

    # Public Azure built-in Key Vault Secrets User role definition ID.
    $secretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6' # gitleaks:allow - Public Azure role ID.
    $readerAssignments = @(
        @(
            az role assignment list `
                --assignee $workloadPrincipalId `
                --scope $vault.id `
                --only-show-errors `
                --output json | ConvertFrom-Json
        ) | Where-Object {
            $_.scope -eq $vault.id -and
            $_.roleDefinitionId.EndsWith(
                "/$secretsUserRoleId",
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    )
    if ($readerAssignments.Count -ne 1) {
        throw 'The GitHub workload identity must have exactly one direct Key Vault Secrets User assignment.'
    }

    return $vault
}
