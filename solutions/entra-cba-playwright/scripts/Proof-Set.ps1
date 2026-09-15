function Get-E2eProofSetId {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][long]$RunId,
        [Parameter(Mandatory)][string]$HeadSha,
        [Parameter(Mandatory)][string]$WorkflowFile,
        [Parameter(Mandatory)][string]$OidcSubject
    )

    if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
        $RunId -le 0 -or
        $HeadSha -notmatch '^[a-f0-9]{40}$' -or
        $WorkflowFile -notmatch '^[A-Za-z0-9_.-]+\.ya?ml$' -or
        [string]::IsNullOrWhiteSpace($OidcSubject)) {
        throw 'The cloud proof identity is incomplete or malformed.'
    }
    $material = [ordered]@{
        headSha = $HeadSha
        oidcSubject = $OidcSubject
        repository = $Repository
        runId = $RunId
        workflowFile = $WorkflowFile
    } | ConvertTo-Json -Compress
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($material)
        )
    ).ToLowerInvariant()
}
