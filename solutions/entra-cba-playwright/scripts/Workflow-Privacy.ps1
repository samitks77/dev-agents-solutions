function Get-TextSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($Text)
        )
    ).ToLowerInvariant()
}

function Get-WorkflowLogProtectedValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Application,
        [Parameter(Mandatory)][object]$Entra,
        [Parameter(Mandatory)][object]$GitHub,
        [Parameter(Mandatory)][object]$Infrastructure,
        [Parameter(Mandatory)][object]$RunnerNetwork
    )

    $protectedValues = [ordered]@{}
    function Add-ProtectedValue {
        param(
            [Parameter(Mandatory)][string]$Category,
            [AllowNull()][object]$Value
        )

        $text = [string]$Value
        if (-not [string]::IsNullOrWhiteSpace($text) -and $text.Length -ge 3) {
            $protectedValues[$Category] = $text
        }
    }

    Add-ProtectedValue -Category 'application client ID' -Value $Application.appId
    Add-ProtectedValue -Category 'application tenant ID' -Value $Application.tenantId
    Add-ProtectedValue -Category 'application URL' -Value $Application.appUrl
    Add-ProtectedValue -Category 'application test username' -Value $Application.testUsername
    if ($Application.appUrl) {
        Add-ProtectedValue `
            -Category 'application hostname' `
            -Value ([Uri]$Application.appUrl).DnsSafeHost
    }

    Add-ProtectedValue -Category 'test-user object ID' -Value $Entra.testUserId
    Add-ProtectedValue -Category 'test-user UPN' -Value $Entra.testUserUpn
    Add-ProtectedValue -Category 'Entra tenant ID' -Value $Entra.tenantId

    Add-ProtectedValue -Category 'immutable OIDC subject' -Value $GitHub.subject
    Add-ProtectedValue -Category 'immutable OIDC subject prefix' -Value $GitHub.subjectPrefix
    Add-ProtectedValue -Category 'workload client ID' -Value $GitHub.workloadClientId

    Add-ProtectedValue -Category 'Azure resource group' -Value $Infrastructure.resourceGroup
    Add-ProtectedValue -Category 'Azure subscription ID' -Value $Infrastructure.subscriptionId
    Add-ProtectedValue -Category 'infrastructure tenant ID' -Value $Infrastructure.tenantId
    foreach ($output in @($Infrastructure.outputs.PSObject.Properties)) {
        if ($null -ne $output.Value -and
            $null -ne $output.Value.PSObject.Properties['value']) {
            Add-ProtectedValue `
                -Category "Azure output '$($output.Name)'" `
                -Value $output.Value.value
        }
    }

    Add-ProtectedValue -Category 'Key Vault name' -Value $RunnerNetwork.keyVaultName
    Add-ProtectedValue `
        -Category 'Key Vault hostname' `
        -Value "$($RunnerNetwork.keyVaultName).vault.azure.net"
    Add-ProtectedValue `
        -Category 'Key Vault private endpoint IP' `
        -Value $RunnerNetwork.privateEndpointIp
    Add-ProtectedValue `
        -Category 'runner outbound IP' `
        -Value $RunnerNetwork.runnerOutboundIp
    Add-ProtectedValue `
        -Category 'runner subnet CIDR' `
        -Value $RunnerNetwork.runnerSubnetCidr
    Add-ProtectedValue `
        -Category 'runner subnet resource ID' `
        -Value $RunnerNetwork.runnerSubnetId

    return $protectedValues
}

function Test-WorkflowLogPrivacy {
    [CmdletBinding(DefaultParameterSetName = 'GitHub')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'GitHub')][string]$Repository,
        [Parameter(Mandatory, ParameterSetName = 'GitHub')][long]$RunId,
        [Parameter(Mandatory, ParameterSetName = 'Text')][AllowEmptyString()][string]$LogText,
        [Parameter(Mandatory)][Collections.IDictionary]$ProtectedValues,
        [Parameter(ParameterSetName = 'GitHub')]
        [ValidateRange(5, 180)]
        [int]$RetrySeconds = 90
    )

    if ($PSCmdlet.ParameterSetName -eq 'GitHub') {
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($RetrySeconds)
        $logLines = @()
        $exitCode = -1
        do {
            $nativePreference = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
            try {
                $logLines = @(
                    & gh run view $RunId --repo $Repository --log 2>$null
                )
                $exitCode = $LASTEXITCODE
            } finally {
                $PSNativeCommandUseErrorActionPreference = $nativePreference
            }
            if ($exitCode -eq 0 -and $logLines.Count -ne 0) {
                break
            }
            Start-Sleep -Seconds 5
        } while ([DateTimeOffset]::UtcNow -lt $deadline)

        if ($exitCode -ne 0 -or $logLines.Count -eq 0) {
            throw "GitHub logs for workflow run '$RunId' were unavailable for privacy verification."
        }
        $LogText = $logLines -join "`n"
    }

    if ([string]::IsNullOrWhiteSpace($LogText)) {
        throw 'Workflow log privacy verification received an empty log.'
    }

    $violations = [Collections.Generic.List[string]]::new()
    $variantCount = 0
    foreach ($entry in $ProtectedValues.GetEnumerator()) {
        $value = ([string]$entry.Value).Trim()
        if ($value.Length -lt 3) {
            continue
        }

        $variants = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        [void]$variants.Add($value)
        [void]$variants.Add([Uri]::EscapeDataString($value))
        [void]$variants.Add(
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))
        )
        $variantCount += $variants.Count

        foreach ($variant in $variants) {
            if ($LogText.Contains($variant, [StringComparison]::OrdinalIgnoreCase)) {
                $violations.Add([string]$entry.Key)
                break
            }
        }
    }

    if ($violations.Count -ne 0) {
        $categories = @($violations | Sort-Object -CaseSensitive -Unique)
        throw (
            'Workflow log privacy verification found protected deployment values in: ' +
            ($categories -join ', ')
        )
    }

    return [pscustomobject]@{
        logSha256 = Get-TextSha256 -Text $LogText
        protectedValueCount = $ProtectedValues.Count
        variantCount = $variantCount
        verifiedAt = [DateTimeOffset]::UtcNow.ToString('o')
    }
}
