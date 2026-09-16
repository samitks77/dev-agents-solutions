[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$labRoot = Split-Path -Parent $PSScriptRoot
$repositoryRoot = (& git -C $labRoot rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repositoryRoot)) {
    throw 'The public-template check must run inside a Git repository.'
}

$solutionPrefix = 'solutions/entra-cba-playwright'
$candidateFiles = @(
    & git -C $repositoryRoot ls-files --cached --others --exclude-standard |
        Where-Object {
            $_ -like "$solutionPrefix/*" -or
            $_ -like '.github/workflows/entra-cba-*'
        }
)
if ($LASTEXITCODE -ne 0 -or $candidateFiles.Count -eq 0) {
    throw 'No public Entra CBA solution files were found.'
}

$sensitivePaths = @(
    $candidateFiles | Where-Object {
        $_ -match '(?i)(^|/)\.env$' -or
        $_ -match '(?i)\.(?:pfx|p12|pem|key|cer|crt)$' -or
        $_ -match '(?i)(^|/)(?:\.auth|\.lab-secrets|\.lab-state|\.artifacts)/'
    }
)
if ($sensitivePaths.Count -ne 0) {
    throw "Sensitive runtime files are publishable: $($sensitivePaths -join ', ')"
}

# These are documented public Microsoft identifiers, not tenant or subscription values.
$allowedPublicGuids = @(
    '00000003-0000-0000-c000-000000000000', # Microsoft Graph resource application
    '14d82eec-204b-4c2f-b7e8-296a70dab67e', # Microsoft Graph PowerShell
    '4200930c-0da2-4e33-ca02-000000000004', # Microsoft-managed CA policy template
    '4633458b-17de-408a-b874-0445c86b69e6', # Key Vault Secrets User
    'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'  # Key Vault Secrets Officer
)
$guidPattern = '(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b'
$ipv4Pattern = '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])'
$subjectKeyIdentifierOid = @(2, 5, 29, 14) -join '.'
$subjectKeyIdentifierSource = "$solutionPrefix/scripts/New-LabPki.ps1"
$forbiddenPatterns = [ordered]@{
    'Entra tenant UPN' = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.onmicrosoft\.com\b'
    'Azure subscription resource ID' = '(?i)/subscriptions/[0-9a-f-]{36}\b'
    'Azure tenant resource ID' = '(?i)/tenants/[0-9a-f-]{36}\b'
    'Deployed Static Web Apps hostname' = '(?i)https://[a-z0-9-]+\.\d+\.azurestaticapps\.net'
    'Local user profile path' = '(?i)(?:file:///)?[a-z]:[/\\]Users[/\\][^/\\\s]+'
    'Hard-coded repository parameter' = '(?i)\[string\]\$Repository\s*=\s*[''"]'
}

$failures = [Collections.Generic.List[string]]::new()
foreach ($relativePath in $candidateFiles) {
    $path = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    $content = Get-Content -LiteralPath $path -Raw
    foreach ($match in [regex]::Matches($content, $guidPattern)) {
        if ($allowedPublicGuids -cnotcontains $match.Value.ToLowerInvariant()) {
            $failures.Add("$relativePath contains non-public GUID '$($match.Value)'.")
        }
    }
    foreach ($match in [regex]::Matches($content, $ipv4Pattern)) {
        $lineStart = $content.LastIndexOf("`n", [Math]::Max(0, $match.Index - 1)) + 1
        $lineEnd = $content.IndexOf("`n", $match.Index)
        if ($lineEnd -lt 0) {
            $lineEnd = $content.Length
        }
        $line = $content.Substring($lineStart, $lineEnd - $lineStart)
        $isSubjectKeyIdentifierOid = (
            $relativePath -ceq $subjectKeyIdentifierSource -and
            $match.Value -ceq $subjectKeyIdentifierOid -and
            $line -match (
                '\.Oid\.Value\s+-eq\s+[''"]' +
                [regex]::Escape($subjectKeyIdentifierOid) +
                '[''"]'
            )
        )
        if (-not $isSubjectKeyIdentifierOid) {
            $failures.Add("$relativePath contains literal IPv4 address or CIDR '$($match.Value)'.")
        }
    }
    foreach ($entry in $forbiddenPatterns.GetEnumerator()) {
        if ([regex]::IsMatch($content, $entry.Value)) {
            $failures.Add("$relativePath contains $($entry.Key).")
        }
    }
}

$examplePath = Join-Path $labRoot '.env.example'
$example = Get-Content -LiteralPath $examplePath -Raw
$requiredPlaceholders = @(
    'CBA_APP_URL=https://<static-web-app-hostname>/',
    'CBA_APP_CLIENT_ID=<entra-application-client-id>',
    'CBA_TENANT_ID=<entra-tenant-id>',
    'CBA_TEST_USERNAME=<dedicated-test-user-upn>',
    'CBA_TEST_OBJECT_ID=<dedicated-test-user-object-id>',
    'CBA_PFX_PATH=<absolute-path-to-test-user-pfx>',
    'CBA_PFX_PASSPHRASE=<inject-at-runtime-do-not-commit>'
)
foreach ($placeholder in $requiredPlaceholders) {
    if (-not $example.Contains($placeholder, [StringComparison]::Ordinal)) {
        $failures.Add(".env.example is missing placeholder '$placeholder'.")
    }
}

if ($failures.Count -ne 0) {
    throw "Public-template validation failed:`n- $($failures -join "`n- ")"
}

Write-Host (
    "PUBLIC_TEMPLATE_PASS files=$($candidateFiles.Count) " +
    "allowedPublicGuids=$($allowedPublicGuids.Count)"
)
