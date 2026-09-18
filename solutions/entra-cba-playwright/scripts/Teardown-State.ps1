function Get-EntraTeardownRetirableStateFileNames {
    return @(
        'auth-strength-negative.json'
        'auth-strength-positive.json'
        'conditional-access-isolation.json'
        'conditional-access-operation.json'
        'conditional-access.json'
        'credentials.json'
        'entra-baseline-operation.json'
        'entra-baseline-context.json'
        'entra-operation.json'
        'entra.json'
        'headed-feasibility.json'
        'headless-reliability.json'
        'local-feasibility.json'
        'pki-baseline.json'
        'pki.json'
        'runner.json'
        'session-reuse.json'
        'sign-in-evidence.json'
        'wrong-origin-control.json'
        'x509-policy-baseline.json'
    )
}

function Get-EntraTeardownFileHash {
    param([Parameter(Mandatory)][string]$Path)

    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

function Write-EntraTeardownStateAtomically {
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
            ($State | ConvertTo-Json -Depth 6),
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

function New-EntraTeardownStateRecord {
    param(
        [Parameter(Mandatory)][string]$StateDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$CompletedAt = [DateTimeOffset]::UtcNow.ToString('o')
    )

    $requiredStateFiles = @(
        'entra.json'
        'pki.json'
        'x509-policy-baseline.json'
    )
    foreach ($fileName in $requiredStateFiles) {
        $path = Join-Path $StateDirectory $fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Completed teardown state is missing required ownership file '$fileName'."
        }
    }

    $stateHashes = [ordered]@{}
    foreach ($fileName in Get-EntraTeardownRetirableStateFileNames) {
        $path = Join-Path $StateDirectory $fileName
        if (Test-Path -LiteralPath $path) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Teardown state path '$fileName' is not a file."
            }
            $stateHashes[$fileName] = Get-EntraTeardownFileHash -Path $path
        }
    }

    return [ordered]@{
        completedAt = $CompletedAt
        isolationRestorationVerified = $false
        retirementStartedAt = $null
        schemaVersion = 3
        stateHashes = $stateHashes
        status = 'completed'
        tenantId = $TenantId
    }
}

function Assert-EntraTeardownTenantBindings {
    param(
        [Parameter(Mandatory)][string]$StateDirectory,
        [Parameter(Mandatory)][string]$TenantId,
        [switch]$AllowMissingFiles
    )

    foreach ($binding in @(
        @{ fileName = 'entra.json'; required = $true }
        @{ fileName = 'conditional-access.json'; required = $false }
        @{ fileName = 'entra-baseline-context.json'; required = $false }
    )) {
        $path = Join-Path $StateDirectory $binding.fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            if ($binding.required -and -not $AllowMissingFiles) {
                throw "Completed teardown state is missing '$($binding.fileName)'."
            }
            continue
        }
        $state = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($state.tenantId -ine $TenantId) {
            throw "Completed teardown state '$($binding.fileName)' belongs to another tenant."
        }
    }

    $baselineContextPath = Join-Path $StateDirectory 'entra-baseline-context.json'
    if (Test-Path -LiteralPath $baselineContextPath -PathType Leaf) {
        $baselineContext = Get-Content -LiteralPath $baselineContextPath -Raw |
            ConvertFrom-Json
        foreach ($baseline in @(
            @{
                hashProperty = 'policySha256'
                path = Join-Path $StateDirectory 'x509-policy-baseline.json'
            }
            @{
                hashProperty = 'pkiSha256'
                path = Join-Path $StateDirectory 'pki-baseline.json'
            }
        )) {
            $expectedHash = $baselineContext.($baseline.hashProperty)
            if (-not $expectedHash) {
                throw 'Completed teardown baselines are not intact and tenant-bound.'
            }
            if (-not (Test-Path -LiteralPath $baseline.path -PathType Leaf)) {
                if ($AllowMissingFiles) {
                    continue
                }
                throw 'Completed teardown baselines are not intact and tenant-bound.'
            }
            if ((Get-EntraTeardownFileHash -Path $baseline.path) -cne $expectedHash) {
                throw 'Completed teardown baselines are not intact and tenant-bound.'
            }
        }
    }
}

function Complete-EntraTeardownStateRetirement {
    param(
        [Parameter(Mandatory)][string]$StateDirectory,
        [Parameter(Mandatory)][string]$TenantId
    )

    $teardownStatePath = Join-Path $StateDirectory 'entra-teardown.json'
    if (-not (Test-Path -LiteralPath $teardownStatePath -PathType Leaf)) {
        throw 'Completed Entra teardown state does not exist.'
    }
    $isolationLockPath = Join-Path $StateDirectory 'conditional-access-isolation.lock'
    try {
        $isolationLockStream = [IO.File]::Open(
            $isolationLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch [IO.IOException] {
        throw 'A Conditional Access isolation transaction is active; PKI regeneration is blocked.'
    }
    $conditionalAccessLockPath = Join-Path `
        $StateDirectory `
        'conditional-access-operation.lock'
    try {
        $conditionalAccessLockStream = [IO.File]::Open(
            $conditionalAccessLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch [IO.IOException] {
        $isolationLockStream.Dispose()
        throw 'Another Conditional Access configuration owns the local lock.'
    }
    $entraLockPath = Join-Path $StateDirectory 'entra-operation.lock'
    try {
        $entraLockStream = [IO.File]::Open(
            $entraLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch [IO.IOException] {
        $isolationLockStream.Dispose()
        $conditionalAccessLockStream.Dispose()
        throw 'Another Entra configuration or teardown transaction owns the local lock.'
    }
    try {
    $teardownState = Get-Content -LiteralPath $teardownStatePath -Raw |
        ConvertFrom-Json
    if (
        $teardownState.status -notin @('completed', 'retiring') -or
        $teardownState.tenantId -ine $TenantId
    ) {
        throw 'Entra teardown is not completed for the selected tenant.'
    }
    $retirementInProgress = $teardownState.status -ceq 'retiring'

    $schemaVersion = if ($teardownState.PSObject.Properties.Name -contains 'schemaVersion') {
        [int]$teardownState.schemaVersion
    }
    else {
        1
    }
    Assert-EntraTeardownTenantBindings `
        -StateDirectory $StateDirectory `
        -TenantId $TenantId `
        -AllowMissingFiles:$retirementInProgress

    if ($schemaVersion -ne 3) {
        throw (
            "Teardown state schema '$schemaVersion' predates verified deletion read-back. " +
            'Rerun Remove-EntraCbaLab.ps1 before PKI regeneration.'
        )
    }
    if ($teardownState.PSObject.Properties.Name -notcontains 'stateHashes') {
        throw 'Completed teardown record does not contain state-hash bindings.'
    }

    $allowedFileNames = @(Get-EntraTeardownRetirableStateFileNames)
    $hashProperties = @($teardownState.stateHashes.PSObject.Properties)
    $recordedFileNames = @($hashProperties.Name)
    if ($retirementInProgress -and (
        $teardownState.PSObject.Properties.Name -notcontains
            'isolationRestorationVerified' -or
        $teardownState.isolationRestorationVerified -ne $true
    )) {
        throw 'Interrupted retirement lacks verified Conditional Access restoration state.'
    }
    foreach ($requiredFileName in @(
        'entra.json'
        'pki.json'
        'x509-policy-baseline.json'
    )) {
        if ($requiredFileName -notin $recordedFileNames) {
            throw "Completed teardown record is missing '$requiredFileName'."
        }
    }
    foreach ($hashProperty in $hashProperties) {
        if (
            $hashProperty.Name -notin $allowedFileNames -or
            [string]$hashProperty.Value -notmatch '^[a-f0-9]{64}$'
        ) {
            throw 'Completed teardown record contains an invalid state-hash binding.'
        }
        $path = Join-Path $StateDirectory $hashProperty.Name
        if (Test-Path -LiteralPath $path) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Completed teardown state '$($hashProperty.Name)' is not a file."
            }
        }
        elseif (-not $retirementInProgress) {
            throw "Completed teardown state '$($hashProperty.Name)' is missing."
        }
        if (
            (Test-Path -LiteralPath $path -PathType Leaf) -and
            (Get-EntraTeardownFileHash -Path $path) -cne [string]$hashProperty.Value
        ) {
            throw "Completed teardown state '$($hashProperty.Name)' was modified."
        }
    }
    foreach ($fileName in $allowedFileNames) {
        $path = Join-Path $StateDirectory $fileName
        if (
            (Test-Path -LiteralPath $path) -and
            $fileName -notin $recordedFileNames
        ) {
            throw "Unrecorded teardown state '$fileName' blocks PKI regeneration."
        }
    }

    $isolationStatePath = Join-Path $StateDirectory 'conditional-access-isolation.json'
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
                'Conditional Access isolation is not verifiably restored for this tenant; ' +
                'run the documented isolation recovery before PKI regeneration.'
            )
        }
    }
    elseif (
        'conditional-access-isolation.json' -in $recordedFileNames -and
        -not $retirementInProgress
    ) {
        throw 'Recorded Conditional Access isolation state is missing.'
    }

    if (-not $retirementInProgress) {
        $teardownState = [ordered]@{
            completedAt = [string]$teardownState.completedAt
            isolationRestorationVerified = $true
            retirementStartedAt = [DateTimeOffset]::UtcNow.ToString('o')
            schemaVersion = 3
            stateHashes = $teardownState.stateHashes
            status = 'retiring'
            tenantId = $TenantId
        }
        Write-EntraTeardownStateAtomically `
            -Path $teardownStatePath `
            -State $teardownState
    }

    foreach ($fileName in $allowedFileNames) {
        $path = Join-Path $StateDirectory $fileName
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    Remove-Item -LiteralPath $teardownStatePath -Force
    }
    finally {
        $isolationLockStream.Dispose()
        $conditionalAccessLockStream.Dispose()
        $entraLockStream.Dispose()
    }
}
