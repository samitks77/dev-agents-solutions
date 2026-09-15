function ConvertTo-X509PolicyPatchBody {
    param([Parameter(Mandatory)][object]$Policy)

    return @{
        '@odata.type' = '#microsoft.graph.x509CertificateAuthenticationMethodConfiguration'
        id = 'X509Certificate'
        state = $Policy.state
        includeTargets = @($Policy.includeTargets)
        excludeTargets = @($Policy.excludeTargets)
        certificateUserBindings = @($Policy.certificateUserBindings)
        authenticationModeConfiguration = $Policy.authenticationModeConfiguration
        issuerHintsConfiguration = $Policy.issuerHintsConfiguration
        crlValidationConfiguration = $Policy.crlValidationConfiguration
        certificateAuthorityScopes = @($Policy.certificateAuthorityScopes)
    }
}

function ConvertTo-NormalizedCertificateIdentifier {
    param([AllowNull()][object]$Value)

    return ([string]$Value).Replace(':', '').Replace(' ', '').ToUpperInvariant()
}

function Assert-ExactLabX509Policy {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$PolicyOid,
        [Parameter(Mandatory)][string]$PkiDisplayName,
        [Parameter(Mandatory)][string]$IssuerSubjectKeyIdentifier
    )

    $targets = @($Policy.includeTargets)
    $excludedTargets = @($Policy.excludeTargets)
    if ($Policy.state -ne 'enabled' -or
        $targets.Count -ne 1 -or
        $targets[0].id -ne $GroupId -or
        $targets[0].targetType -ne 'group' -or
        $targets[0].isRegistrationRequired -ne $false -or
        $excludedTargets.Count -ne 0) {
        throw 'The X.509 authentication-method target scope is not the exact lab group.'
    }

    $bindings = @($Policy.certificateUserBindings)
    if ($bindings.Count -ne 1 -or
        [int]$bindings[0].priority -ne 1 -or
        $bindings[0].x509CertificateField -ne 'PrincipalName' -or
        $bindings[0].userProperty -ne 'userPrincipalName') {
        throw 'The X.509 certificate-to-user binding is not the exact lab binding.'
    }

    $mode = $Policy.authenticationModeConfiguration
    $rules = @($mode.rules)
    if ($mode.x509CertificateAuthenticationDefaultMode -ne 'x509CertificateSingleFactor' -or
        $rules.Count -ne 1 -or
        $rules[0].identifier -ne $PolicyOid -or
        $rules[0].x509CertificateAuthenticationMode -ne 'x509CertificateMultiFactor' -or
        $rules[0].x509CertificateRuleType -ne 'policyOID') {
        throw 'The X.509 authentication modes do not match the single-factor default and MFA policy OID.'
    }

    if ($Policy.issuerHintsConfiguration.state -ne 'disabled' -or
        $Policy.crlValidationConfiguration.state -ne 'enabled' -or
        @($Policy.crlValidationConfiguration.exemptedCertificateAuthoritiesSubjectKeyIdentifiers).Count -ne 0) {
        throw 'Issuer hints or CRL validation do not match the fail-closed lab policy.'
    }

    $authorityScopes = @($Policy.certificateAuthorityScopes)
    $authorityTargets = @($authorityScopes[0].includeTargets)
    $authorityExcludedTargets = @($authorityScopes[0].excludeTargets)
    if ($authorityScopes.Count -ne 1 -or
        $authorityTargets.Count -ne 1 -or
        $authorityExcludedTargets.Count -ne 0 -or
        $authorityTargets[0].id -ne $GroupId -or
        $authorityTargets[0].targetType -ne 'group' -or
        $authorityScopes[0].publicKeyInfrastructureIdentifier -cne $PkiDisplayName -or
        (ConvertTo-NormalizedCertificateIdentifier $authorityScopes[0].subjectKeyIdentifier) -cne
            (ConvertTo-NormalizedCertificateIdentifier $IssuerSubjectKeyIdentifier)) {
        throw 'The certificate-authority scope does not match the exact lab group, PKI, and issuer.'
    }
}

function Assert-ExactLabCertificateAuthority {
    param(
        [Parameter(Mandatory)][object]$CertificateAuthority,
        [Parameter(Mandatory)][object]$PkiState,
        [Parameter(Mandatory)][string]$ExpectedId
    )

    $actualExpiration = [DateTimeOffset]::Parse(
        [string]$CertificateAuthority.expirationDateTime
    ).ToUniversalTime()
    $expectedExpiration = [DateTimeOffset]::Parse(
        [string]$PkiState.ca.expirationDateTime
    ).ToUniversalTime()
    if ($CertificateAuthority.id -ne $ExpectedId -or
        $CertificateAuthority.displayName -cne 'Entra CBA Playwright POC Root CA' -or
        $CertificateAuthority.certificateAuthorityType -ne 'root' -or
        $CertificateAuthority.certificateRevocationListUrl -cne $PkiState.crlUrl -or
        $CertificateAuthority.deltaCertificateRevocationListUrl -or
        $CertificateAuthority.isIssuerHintEnabled -ne $false -or
        (ConvertTo-NormalizedCertificateIdentifier $CertificateAuthority.thumbprint) -cne
            (ConvertTo-NormalizedCertificateIdentifier $PkiState.ca.thumbprint) -or
        (ConvertTo-NormalizedCertificateIdentifier $CertificateAuthority.issuerSubjectKeyIdentifier) -cne
            (ConvertTo-NormalizedCertificateIdentifier $PkiState.ca.subjectKeyIdentifier) -or
        [Math]::Abs(($actualExpiration - $expectedExpiration).TotalSeconds) -gt 1) {
        throw 'The trusted certificate authority does not exactly match the generated lab root CA.'
    }
}
