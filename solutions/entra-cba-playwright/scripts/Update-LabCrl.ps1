[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$ValidityDays = 37
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$statePath = Join-Path $labRoot '.lab-state\pki.json'
$secretDirectory = Join-Path $labRoot '.lab-secrets'
$configurationPath = Join-Path $secretDirectory 'openssl.cnf'
if (-not (Test-Path -LiteralPath $statePath) -or
    -not (Test-Path -LiteralPath $configurationPath)) {
    throw 'Existing PKI state and OpenSSL configuration are required to renew the CRL.'
}

$pki = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$latestCertificateExpiry = @(
    $pki.certificates | ForEach-Object { [DateTimeOffset]::Parse($_.notAfter) }
) | Sort-Object -Descending | Select-Object -First 1
if ([DateTimeOffset]::UtcNow.AddDays($ValidityDays) -le $latestCertificateExpiry) {
    throw 'The renewed CRL must remain valid beyond every issued user certificate.'
}
if ([DateTimeOffset]::UtcNow.AddDays($ValidityDays) -ge
    [DateTimeOffset]::Parse($pki.ca.expirationDateTime)) {
    throw 'The renewed CRL must expire before the root CA certificate.'
}

$opensslCandidates = @(
    'C:\Program Files\Git\usr\bin\openssl.exe',
    'C:\Program Files\Git\mingw64\bin\openssl.exe'
)
$openssl = $opensslCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $openssl) {
    throw 'OpenSSL 3 is required to renew the lab CRL.'
}

$caPassphrasePath = Join-Path $secretDirectory 'private\ca-passphrase.clixml'
$caPassphrase = Import-Clixml -LiteralPath $caPassphrasePath
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($caPassphrase)
try {
    $env:CBA_CA_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $caPassphrase = $null
}

$crlPath = [string]$pki.ca.crlPath
$crlPemPath = [IO.Path]::ChangeExtension($crlPath, '.crl.pem')
$temporaryPemPath = "$crlPemPath.new"
$temporaryDerPath = "$crlPath.new"
try {
    & $openssl ca `
        -gencrl `
        -config $configurationPath `
        -passin env:CBA_CA_PASSWORD `
        -crldays $ValidityDays `
        -crlexts crl_ext `
        -out $temporaryPemPath
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL CRL renewal failed with exit code $LASTEXITCODE."
    }
    & $openssl crl -in $temporaryPemPath -outform DER -out $temporaryDerPath
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL CRL conversion failed with exit code $LASTEXITCODE."
    }
    & $openssl crl `
        -in $temporaryDerPath `
        -inform DER `
        -noout `
        -verify `
        -CAfile (Join-Path $secretDirectory 'public\lab-root-ca.pem')
    if ($LASTEXITCODE -ne 0) {
        throw "Renewed CRL signature verification failed with exit code $LASTEXITCODE."
    }

    $nextUpdateText = (
        & $openssl crl -in $temporaryDerPath -inform DER -noout -nextupdate
    ) -join ''
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the renewed CRL nextUpdate value."
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

    Move-Item -LiteralPath $temporaryPemPath -Destination $crlPemPath -Force
    Move-Item -LiteralPath $temporaryDerPath -Destination $crlPath -Force
    $pki.ca | Add-Member `
        -MemberType NoteProperty `
        -Name crlNextUpdate `
        -Value $nextUpdate.ToString('o') `
        -Force
    $pki.ca | Add-Member `
        -MemberType NoteProperty `
        -Name crlSha256 `
        -Value (
        Get-FileHash -LiteralPath $crlPath -Algorithm SHA256
    ).Hash.ToLowerInvariant() `
        -Force
    $pki | Add-Member `
        -MemberType NoteProperty `
        -Name crlValidityDays `
        -Value $ValidityDays `
        -Force
    $pki | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statePath -Encoding utf8NoBOM
} finally {
    Remove-Item Env:CBA_CA_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryPemPath, $temporaryDerPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Lab CRL renewed through $($pki.ca.crlNextUpdate)."
Write-Host 'Redeploy the test application, then run Test-PublishedCrl.ps1.'
