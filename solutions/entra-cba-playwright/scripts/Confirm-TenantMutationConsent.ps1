function Test-InteractiveLabSession {
    <#
    .SYNOPSIS
    Returns $true only when this process can safely prompt an operator for typed confirmation.

    .DESCRIPTION
    Fails closed: any ambiguity (redirected input, no console, non-interactive host) is treated as
    non-interactive so that a missing or automated console never silently satisfies a confirmation
    prompt.
    #>
    if ([Environment]::UserInteractive -eq $false) {
        return $false
    }
    try {
        if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
            return $false
        }
    } catch {
        return $false
    }
    if (-not $Host -or -not $Host.UI -or -not $Host.UI.RawUI) {
        return $false
    }
    return $true
}

function Confirm-TenantMutationConsent {
    <#
    .SYNOPSIS
    Fail-closed consent gate for any script that is about to perform tenant, Conditional Access,
    or GitHub-repository mutations.

    .DESCRIPTION
    Shared by Bootstrap-PostDeploy.ps1 and Invoke-EntraCbaVerification.ps1 (Tier C) so both entry
    points show the exact same scope banner and enforce the exact same confirmation contract
    instead of each re-implementing it:

    - Always prints the tenant ID, subscription ID, GitHub repository, and the specific mutation
      list before anything else runs.
    - Requires the explicit -ConfirmSwitch acknowledgement; its absence aborts immediately,
      regardless of interactivity.
    - In an interactive session, additionally requires the operator to type the literal word
      CONFIRM (not merely press Enter or answer y/n).
    - In a non-interactive session, requires a second, independent confirmation via the
      ENTRA_CBA_BOOTSTRAP_AUTOAPPROVE environment variable set to the exact literal value
      'CONFIRMED'. A missing, blank, or differently-cased value aborts. Silence, defaults, and
      ambiguous state are never treated as consent.

    .OUTPUTS
    Throws (aborts) unless explicit consent was obtained. Never returns a falsy "continue anyway"
    value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string[]]$PendingMutations,
        [Parameter(Mandatory)][bool]$ConfirmSwitch,
        [string]$AutoApproveEnvironmentVariableName = 'ENTRA_CBA_BOOTSTRAP_AUTOAPPROVE',
        [string]$RequiredAutoApproveValue = 'CONFIRMED',
        [string]$RequiredTypedConfirmation = 'CONFIRM'
    )

    $mutationList = ($PendingMutations | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
    $banner = @"
================================================================================
 EXPLICIT CONSENT REQUIRED BEFORE ANY TENANT OR GITHUB MUTATION
================================================================================
 Tenant ID:         $TenantId
 Subscription ID:   $SubscriptionId
 GitHub repository: $Repository

 The following mutating operations will run, in order, if you continue:
$mutationList

 This operation changes the tenant-wide Entra CBA authentication-method policy
 and the selected GitHub repository. Use an isolated test tenant or an approved
 exclusive maintenance window. Existing users, groups, PKI containers, CAs,
 and Conditional Access policies are rejected unless exact ignored local state
 proves this solution created them. Review the operation-specific mutation and
 restoration steps above before granting consent.
================================================================================
"@
    Write-Host $banner

    if (-not $ConfirmSwitch) {
        throw (
            'Refusing to continue: re-run with the explicit consent switch after reviewing the ' +
            'exact scope printed above. This command never proceeds on a default or missing flag.'
        )
    }

    $autoApproveValue = [Environment]::GetEnvironmentVariable($AutoApproveEnvironmentVariableName)
    $isDoubleConfirmedNonInteractive = ($autoApproveValue -ceq $RequiredAutoApproveValue)
    $isInteractive = Test-InteractiveLabSession

    if (-not $isInteractive) {
        if (-not $isDoubleConfirmedNonInteractive) {
            throw (
                "Refusing to continue in a non-interactive session: set the environment variable " +
                "'$AutoApproveEnvironmentVariableName=$RequiredAutoApproveValue' in addition to the " +
                'consent switch to intentionally opt in to unattended execution. Any other or ' +
                'missing value aborts (fail closed).'
            )
        }
        Write-Host (
            "Non-interactive double confirmation verified: consent switch plus " +
            "'$AutoApproveEnvironmentVariableName=$RequiredAutoApproveValue'."
        )
        return
    }

    # Even when the operator intentionally set the auto-approve environment variable, an
    # interactive session always requires the typed word so a stray inherited environment
    # variable can never silently authorize a live human-attended run.
    $typed = Read-Host "Type $RequiredTypedConfirmation to proceed with the mutations listed above"
    if ($typed -cne $RequiredTypedConfirmation) {
        throw (
            "Confirmation not received (expected the literal word '$RequiredTypedConfirmation'); " +
            'aborting without making any change.'
        )
    }
    Write-Host 'Typed confirmation received. Proceeding.'
}
