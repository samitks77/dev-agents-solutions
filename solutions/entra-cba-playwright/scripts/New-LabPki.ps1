[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TestUserUpn,
    [string]$PolicyOid = '1.3.6.1.4.1.55555.1.1',
    [string]$CrlUrl,
    [int]$CaValidityDays = 90,
    [int]$UserCertificateValidityDays = 30,
    [ValidateRange(0, 365)][int]$CrlValidityDays = 0,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$stateDirectory = Join-Path $labRoot '.lab-state'
$infrastructureStatePath = Join-Path $stateDirectory 'infrastructure.json'
$outputDirectory = Join-Path $labRoot '.lab-secrets'
$publicDirectory = Join-Path $outputDirectory 'public'
$privateDirectory = Join-Path $outputDirectory 'private'
$newCertificatesDirectory = Join-Path $outputDirectory 'newcerts'
$opensslConfigurationPath = Join-Path $outputDirectory 'openssl.cnf'
$manifestPath = Join-Path $stateDirectory 'pki.json'

if (-not $CrlUrl) {
    if (-not (Test-Path $infrastructureStatePath)) {
        throw 'Supply -CrlUrl or deploy the infrastructure first.'
    }
    $infrastructure = Get-Content $infrastructureStatePath -Raw | ConvertFrom-Json
    $CrlUrl = $infrastructure.outputs.crlUrl.value
}

if (-not $CrlUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase) -and
    -not $CrlUrl.StartsWith('http://', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The CRL URL must be an internet-facing HTTP or HTTPS URL.'
}
$effectiveCrlValidityDays = if ($CrlValidityDays -eq 0) {
    $UserCertificateValidityDays + 7
} else {
    $CrlValidityDays
}
if ($effectiveCrlValidityDays -le $UserCertificateValidityDays) {
    throw 'The CRL validity must extend beyond the user-certificate validity.'
}
if ($effectiveCrlValidityDays -ge $CaValidityDays) {
    throw 'The CRL must expire before the root CA certificate.'
}

$opensslCandidates = @(
    'C:\Program Files\Git\usr\bin\openssl.exe',
    'C:\Program Files\Git\mingw64\bin\openssl.exe'
)
$openssl = $opensslCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $openssl) {
    throw 'OpenSSL 3 is required; install Git for Windows or OpenSSL and update the script path.'
}

if ((Test-Path $manifestPath) -and -not $Force) {
    throw "PKI state already exists at '$manifestPath'; use -Force only to replace this disposable lab PKI."
}

if ($Force -and (Test-Path $outputDirectory)) {
    Remove-Item $outputDirectory -Recurse -Force
}

New-Item -ItemType Directory -Path $stateDirectory, $outputDirectory, $publicDirectory, $privateDirectory, $newCertificatesDirectory -Force | Out-Null
[IO.File]::WriteAllBytes((Join-Path $outputDirectory 'index.txt'), [byte[]]::new(0))
Set-Content -Path (Join-Path $outputDirectory 'serial') -Value '1000' -Encoding ascii
Set-Content -Path (Join-Path $outputDirectory 'crlnumber') -Value '1000' -Encoding ascii

function New-ProtectedPassphrase {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path $Path) {
        return Import-Clixml -Path $Path
    }

    $bytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $plain = [Convert]::ToHexString($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    $plain = $null
    $secure | Export-Clixml -Path $Path
    return $secure
}

function ConvertFrom-ProtectedString {
    param([Parameter(Mandatory)][Security.SecureString]$Value)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Invoke-OpenSsl {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & $openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed with exit code $LASTEXITCODE."
    }
}

$caPassphrasePath = Join-Path $privateDirectory 'ca-passphrase.clixml'
$pfxPassphrasePath = Join-Path $privateDirectory 'pfx-passphrase.clixml'
$caPassphrase = New-ProtectedPassphrase -Path $caPassphrasePath
$pfxPassphrase = New-ProtectedPassphrase -Path $pfxPassphrasePath

$normalizedDirectory = $outputDirectory.Replace('\', '/')
$configuration = @"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = $normalizedDirectory
certs = `$dir
crl_dir = `$dir
new_certs_dir = `$dir/newcerts
database = `$dir/index.txt
serial = `$dir/serial
crlnumber = `$dir/crlnumber
certificate = `$dir/public/lab-root-ca.pem
private_key = `$dir/private/lab-root-ca.key.pem
default_days = $UserCertificateValidityDays
default_crl_days = $effectiveCrlValidityDays
default_md = sha256
policy = policy_match
unique_subject = no
copy_extensions = none

[ policy_match ]
commonName = supplied
organizationName = optional
countryName = optional

[ req ]
default_bits = 3072
distinguished_name = root_dn
prompt = no
x509_extensions = root_ca

[ root_dn ]
C = US
O = Entra CBA Playwright POC
CN = Entra CBA Playwright POC Root CA

[ root_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,digitalSignature,cRLSign,keyCertSign

[ user_mfa_cert ]
basicConstraints = critical,CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @user_alt_names
certificatePolicies = $PolicyOid
crlDistributionPoints = URI:$CrlUrl

[ user_sfa_cert ]
basicConstraints = critical,CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @user_alt_names
crlDistributionPoints = URI:$CrlUrl

[ user_alt_names ]
otherName.1 = 1.3.6.1.4.1.311.20.2.3;UTF8:$TestUserUpn
email.1 = $TestUserUpn

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"@
Set-Content -Path $opensslConfigurationPath -Value $configuration -Encoding ascii

$caPlain = ConvertFrom-ProtectedString $caPassphrase
$pfxPlain = ConvertFrom-ProtectedString $pfxPassphrase
$env:CBA_CA_PASSWORD = $caPlain
$env:CBA_PFX_PASSWORD = $pfxPlain
$caPlain = $null
$pfxPlain = $null

try {
    $caKeyPath = Join-Path $privateDirectory 'lab-root-ca.key.pem'
    $caPemPath = Join-Path $publicDirectory 'lab-root-ca.pem'
    $caDerPath = Join-Path $publicDirectory 'lab-root-ca.cer'
    $crlPemPath = Join-Path $publicDirectory 'entra-cba-lab.crl.pem'
    $crlDerPath = Join-Path $publicDirectory 'entra-cba-lab.crl'

    Invoke-OpenSsl @(
        'genpkey', '-algorithm', 'RSA',
        '-pkeyopt', 'rsa_keygen_bits:3072',
        '-aes-256-cbc',
        '-pass', 'env:CBA_CA_PASSWORD',
        '-out', $caKeyPath
    )
    Invoke-OpenSsl @(
        'req', '-new', '-x509',
        '-config', $opensslConfigurationPath,
        '-key', $caKeyPath,
        '-passin', 'env:CBA_CA_PASSWORD',
        '-days', $CaValidityDays.ToString(),
        '-sha256',
        '-extensions', 'root_ca',
        '-out', $caPemPath
    )
    Invoke-OpenSsl @('x509', '-in', $caPemPath, '-outform', 'DER', '-out', $caDerPath)

    $certificateDefinitions = @(
        @{ Name = 'cba-playwright-test-mfa'; Extension = 'user_mfa_cert' },
        @{ Name = 'cba-playwright-test-sfa'; Extension = 'user_sfa_cert' }
    )

    $issuedCertificates = foreach ($definition in $certificateDefinitions) {
        $keyPath = Join-Path $privateDirectory "$($definition.Name).key.pem"
        $csrPath = Join-Path $privateDirectory "$($definition.Name).csr.pem"
        $certificatePemPath = Join-Path $publicDirectory "$($definition.Name).cert.pem"
        $certificateDerPath = Join-Path $publicDirectory "$($definition.Name).cer"
        $pfxPath = Join-Path $privateDirectory "$($definition.Name).pfx"

        Invoke-OpenSsl @(
            'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:2048',
            '-out', $keyPath
        )
        Invoke-OpenSsl @(
            'req', '-new',
            '-key', $keyPath,
            '-subj', "/C=US/O=Entra CBA Playwright POC/CN=$TestUserUpn",
            '-out', $csrPath
        )
        Invoke-OpenSsl @(
            'ca', '-batch',
            '-config', $opensslConfigurationPath,
            '-extensions', $definition.Extension,
            '-in', $csrPath,
            '-out', $certificatePemPath,
            '-passin', 'env:CBA_CA_PASSWORD'
        )
        Invoke-OpenSsl @('x509', '-in', $certificatePemPath, '-outform', 'DER', '-out', $certificateDerPath)
        Invoke-OpenSsl @(
            'pkcs12', '-export',
            '-inkey', $keyPath,
            '-in', $certificatePemPath,
            '-certfile', $caPemPath,
            '-passout', 'env:CBA_PFX_PASSWORD',
            '-out', $pfxPath
        )

        $certificate = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile($certificateDerPath)
        [ordered]@{
            name = $definition.Name
            certificatePath = $certificateDerPath
            pfxPath = $pfxPath
            thumbprint = $certificate.Thumbprint
            notAfter = $certificate.NotAfter.ToUniversalTime().ToString('o')
        }
    }

    Invoke-OpenSsl @(
        'ca', '-gencrl',
        '-config', $opensslConfigurationPath,
        '-passin', 'env:CBA_CA_PASSWORD',
        '-crlexts', 'crl_ext',
        '-out', $crlPemPath
    )
    Invoke-OpenSsl @('crl', '-in', $crlPemPath, '-outform', 'DER', '-out', $crlDerPath)
    $crlNextUpdateText = (
        Invoke-OpenSsl @('crl', '-in', $crlDerPath, '-inform', 'DER', '-noout', '-nextupdate')
    ) -join ''
    $crlNextUpdateValue = [regex]::Replace(
        ($crlNextUpdateText -replace '^nextUpdate=', '').Trim(),
        '\s+',
        ' '
    )
    $crlNextUpdate = [DateTimeOffset]::ParseExact(
        $crlNextUpdateValue,
        "MMM d HH:mm:ss yyyy 'GMT'",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal
    ).ToUniversalTime()

    $caCertificate = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadCertificateFromFile($caDerPath)
    $subjectKeyIdentifier = $caCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.14' } |
        ForEach-Object { $_.Format($false).Replace(' ', '') }

    $manifest = [ordered]@{
        ca = [ordered]@{
            certificatePath = $caDerPath
            crlNextUpdate = $crlNextUpdate.ToString('o')
            crlPath = $crlDerPath
            crlSha256 = (Get-FileHash -LiteralPath $crlDerPath -Algorithm SHA256).Hash.ToLowerInvariant()
            expirationDateTime = $caCertificate.NotAfter.ToUniversalTime().ToString('o')
            subjectKeyIdentifier = $subjectKeyIdentifier
            thumbprint = $caCertificate.Thumbprint
        }
        certificates = $issuedCertificates
        crlValidityDays = $effectiveCrlValidityDays
        crlUrl = $CrlUrl
        policyOid = $PolicyOid
        privateStateDirectory = $privateDirectory
        pfxPassphrasePath = $pfxPassphrasePath
        testUserUpn = $TestUserUpn
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding utf8NoBOM
} finally {
    Remove-Item Env:CBA_CA_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:CBA_PFX_PASSWORD -ErrorAction SilentlyContinue
}

Write-Host "Lab PKI generated for '$TestUserUpn'."
Write-Host "Public CA certificate: $($manifest.ca.certificatePath)"
Write-Host "Public CRL: $($manifest.ca.crlPath)"
Write-Host "Private material remains under the ignored directory '$privateDirectory'."
