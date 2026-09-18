function Assert-ExactFederatedCredentialSet {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Credentials,
        [Parameter(Mandatory)][string]$ExpectedName,
        [Parameter(Mandatory)][string]$ExpectedIssuer,
        [Parameter(Mandatory)][string]$ExpectedSubject,
        [Parameter(Mandatory)][string]$ExpectedAudience
    )

    if ($Credentials.Count -ne 1) {
        throw (
            'The workload identity must have exactly one federated credential; ' +
            "found $($Credentials.Count)."
        )
    }
    $credential = $Credentials[0]
    if (
        $credential.name -cne $ExpectedName -or
        $credential.issuer -cne $ExpectedIssuer -or
        $credential.subject -cne $ExpectedSubject -or
        @($credential.audiences).Count -ne 1 -or
        $credential.audiences[0] -cne $ExpectedAudience
    ) {
        throw 'The workload identity federated credential set differs from the exact lab contract.'
    }
    return $credential
}
