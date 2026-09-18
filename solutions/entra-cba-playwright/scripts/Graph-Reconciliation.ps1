function Get-GraphCollectionResponse {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [scriptblock]$InvokeRequest = {
            param([string]$RequestUri)
            Invoke-MgGraphRequest -Method GET -Uri $RequestUri
        }
    )

    $firstResponse = $null
    $items = [Collections.Generic.List[object]]::new()
    $visitedUris = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    while ($Uri) {
        if (-not $visitedUris.Add($Uri)) {
            throw "Microsoft Graph returned a repeated collection page URI '$Uri'."
        }
        $response = & $InvokeRequest $Uri
        if ($null -eq $response) {
            throw "Microsoft Graph returned no collection response for '$Uri'."
        }
        if (-not $firstResponse) {
            $firstResponse = $response
        }

        if ($response -is [Collections.IDictionary]) {
            if (-not $response.Contains('value')) {
                throw "Microsoft Graph collection response for '$Uri' has no value property."
            }
            $pageItems = @($response['value'])
            $Uri = if ($response.Contains('@odata.nextLink')) {
                [string]$response['@odata.nextLink']
            }
            else {
                $null
            }
        }
        else {
            $valueProperty = $response.PSObject.Properties['value']
            if ($null -eq $valueProperty) {
                throw "Microsoft Graph collection response for '$Uri' has no value property."
            }
            $pageItems = @($valueProperty.Value)
            $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
            $Uri = if ($null -ne $nextLinkProperty) {
                [string]$nextLinkProperty.Value
            }
            else {
                $null
            }
        }
        foreach ($item in $pageItems) {
            $items.Add($item)
        }
    }
    if (-not $firstResponse) {
        throw 'Microsoft Graph returned no collection response.'
    }

    if ($firstResponse -is [Collections.IDictionary]) {
        $firstResponse['value'] = $items.ToArray()
        $firstResponse.Remove('@odata.nextLink')
    }
    else {
        $firstResponse.value = $items.ToArray()
        $firstResponse.PSObject.Properties.Remove('@odata.nextLink')
    }
    return $firstResponse
}

function Get-GraphCollection {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [scriptblock]$InvokeRequest = {
            param([string]$RequestUri)
            Invoke-MgGraphRequest -Method GET -Uri $RequestUri
        }
    )

    $response = Get-GraphCollectionResponse `
        -Uri $Uri `
        -InvokeRequest $InvokeRequest
    if ($response -is [Collections.IDictionary]) {
        return @($response['value'])
    }
    return @($response.value)
}

function Get-ReconciledGraphMatches {
    param(
        [Parameter(Mandatory)][scriptblock]$Lookup,
        [switch]$WaitForAppearance,
        [ValidateRange(1, 3600)][int]$AppearanceSeconds = 600,
        [ValidateRange(1, 600)][int]$AbsenceSeconds = 30,
        [ValidateRange(1, 60)][int]$PollSeconds = 10,
        [ValidateRange(1, 10)][int]$RequiredAbsenceChecks = 3,
        [scriptblock]$GetNow = { Get-Date },
        [scriptblock]$Sleep = {
            param([int]$Seconds)
            Start-Sleep -Seconds $Seconds
        },
        [string]$FailureMessage = (
            'Microsoft Graph object absence could not be proven after the appearance window.'
        )
    )

    $startedAt = [DateTimeOffset](& $GetNow)
    $appearanceDeadline = $startedAt.AddSeconds($AppearanceSeconds)
    $absenceDeadline = $appearanceDeadline.AddSeconds($AbsenceSeconds)
    $consecutiveAbsenceChecks = 0

    while ($true) {
        $matches = @(& $Lookup)
        if ($matches.Count -ne 0 -or -not $WaitForAppearance) {
            return $matches
        }

        $now = [DateTimeOffset](& $GetNow)
        if ($now -ge $appearanceDeadline) {
            $consecutiveAbsenceChecks++
            if ($consecutiveAbsenceChecks -ge $RequiredAbsenceChecks) {
                return @()
            }
        }
        if ($now -ge $absenceDeadline) {
            break
        }

        $remainingSeconds = [int][Math]::Ceiling(
            ($absenceDeadline - $now).TotalSeconds
        )
        & $Sleep ([Math]::Min($PollSeconds, [Math]::Max(1, $remainingSeconds)))
    }

    throw $FailureMessage
}
