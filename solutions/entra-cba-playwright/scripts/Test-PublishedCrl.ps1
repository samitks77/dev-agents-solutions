[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$pkiStatePath = Join-Path $labRoot '.lab-state\pki.json'
if (-not (Test-Path -LiteralPath $pkiStatePath)) {
    throw "PKI state not found at '$pkiStatePath'."
}
$pki = Get-Content -LiteralPath $pkiStatePath -Raw | ConvertFrom-Json
foreach ($requiredValue in @(
    $pki.ca.certificatePath,
    $pki.ca.crlNextUpdate,
    $pki.ca.crlPath,
    $pki.ca.crlSha256,
    $pki.ca.subjectKeyIdentifier,
    $pki.crlUrl
)) {
    if (-not $requiredValue) {
        throw 'PKI state does not contain complete CRL verification metadata.'
    }
}

$opensslCandidates = @(
    'C:\Program Files\Git\usr\bin\openssl.exe',
    'C:\Program Files\Git\mingw64\bin\openssl.exe'
)
$openssl = $opensslCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $openssl) {
    throw 'OpenSSL 3 is required to verify the published CRL.'
}

$downloadPath = Join-Path ([IO.Path]::GetTempPath()) "entra-cba-crl-$([guid]::NewGuid().ToString('N')).crl"
$rootPemPath = "$downloadPath.root.pem"
try {
    $verificationUrl = "$($pki.crlUrl)?verification=$([guid]::NewGuid().ToString('N'))"
    $response = Invoke-WebRequest -Uri $verificationUrl -OutFile $downloadPath -PassThru
    if ($response.StatusCode -ne 200) {
        throw "Published CRL returned HTTP $($response.StatusCode)."
    }

    $publishedHash = (
        Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $localHash = (
        Get-FileHash -LiteralPath $pki.ca.crlPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($localHash -cne $pki.ca.crlSha256 -or $publishedHash -cne $localHash) {
        throw 'The published CRL bytes do not match the generated CRL and recorded SHA-256.'
    }

    & $openssl x509 `
        -in $pki.ca.certificatePath `
        -inform DER `
        -outform PEM `
        -out $rootPemPath
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to convert the root CA for CRL verification."
    }
    & $openssl crl `
        -in $downloadPath `
        -inform DER `
        -noout `
        -verify `
        -CAfile $rootPemPath
    if ($LASTEXITCODE -ne 0) {
        throw 'The published CRL signature is invalid.'
    }

    $crlIssuer = ((& $openssl crl -in $downloadPath -inform DER -noout -issuer) -join '') -replace '^issuer=\s*', ''
    $caSubject = ((& $openssl x509 -in $pki.ca.certificatePath -inform DER -noout -subject) -join '') -replace '^subject=\s*', ''
    if ($LASTEXITCODE -ne 0 -or $crlIssuer -cne $caSubject) {
        throw 'The published CRL issuer does not match the lab root CA.'
    }

    $crlText = (& $openssl crl -in $downloadPath -inform DER -noout -text) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect the published CRL extensions.'
    }
    $akiMatch = [regex]::Match(
        $crlText,
        'X509v3 Authority Key Identifier:\s*\r?\n\s*([0-9A-Fa-f:]+)'
    )
    $actualAki = $akiMatch.Groups[1].Value.Replace(':', '').ToUpperInvariant()
    $expectedAki = ([string]$pki.ca.subjectKeyIdentifier).Replace(':', '').Replace(' ', '').ToUpperInvariant()
    if (-not $akiMatch.Success -or $actualAki -cne $expectedAki) {
        throw 'The published CRL authority key identifier does not match the lab root CA.'
    }

    $nextUpdateText = (
        & $openssl crl -in $downloadPath -inform DER -noout -nextupdate
    ) -join ''
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to read the published CRL nextUpdate value.'
    }
    $nextUpdateValue = [regex]::Replace(
        ($nextUpdateText -replace '^nextUpdate=', '').Trim(),
        '\s+',
        ' '
    )
    $nextUpdate = [DateTimeOffset]::ParseExact(
        $nextUpdateValue,
        "MMM d HH:mm:ss yyyy 'GMT'",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal
    ).ToUniversalTime()
    if ($nextUpdate -ne [DateTimeOffset]::Parse($pki.ca.crlNextUpdate).ToUniversalTime() -or
        $nextUpdate -le [DateTimeOffset]::UtcNow.AddDays(1)) {
        throw 'The published CRL nextUpdate value is stale or differs from local state.'
    }
} finally {
    Remove-Item -LiteralPath $downloadPath, $rootPemPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Published CRL verified: SHA-256 $publishedHash, nextUpdate $($nextUpdate.ToString('o'))."
