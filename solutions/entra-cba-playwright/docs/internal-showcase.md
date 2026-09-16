# Internal Showcase: Verified Playwright Authentication

This is the operator sequence for demonstrating the solution to an internal engineering or
security audience. It is designed to show evidence, not ask the audience to trust narration.

## Safe demo modes

| Mode | Duration | Tenant mutation | Purpose |
|---|---:|---:|---|
| Evidence replay | 5–10 minutes | None | Recommended meeting demo. Requeries GitHub and Azure, re-hashes bounded receipts and validates the completed Entra evidence and restoration journal. |
| Fresh cloud-runner run | 5–10 minutes | GitHub runner registration plus temporary ACI compute | Repeats the GitHub → Azure → Key Vault → Playwright gate and verifies cleanup. |
| Fresh Conditional Access proof | At least 57 minutes with the documented values | Yes, bounded and restored | Repeats positive/negative policy causality. Requires Graph authorization and an exclusive maintenance window. Do not begin this inside a short meeting. |

## Presenter preflight

Run from `solutions/entra-cba-playwright`:

```powershell
az account show --query "{subscription:id, tenant:tenantId, user:user.name}"
gh auth status
git status --short --branch
```

Stop if Azure or GitHub resolves to a different account, tenant, subscription or repository. Never
display a device-code token, PFX passphrase, private key, access token, raw sign-in record or
GitHub runner registration token.

## Ten-minute evidence replay

### 1. State the acceptance contract

Open [the requirement matrix](enterprise-par-requirement-proof.md). Emphasize:

- real Entra user authentication, not a mocked session;
- no password or broad MFA bypass;
- fixed NAT egress and private Key Vault retrieval;
- exact run, identity, policy and cleanup correlation;
- Private Endpoint is required for Key Vault; Private Link Service is not part of this
  outbound-only design.

### 2. Show the implementation path

Open:

- [the GitHub workflow](../../../.github/workflows/entra-cba-playwright-poc.yml);
- [the ephemeral runner launcher](../scripts/Start-EphemeralGitHubRunner.ps1);
- [the Playwright client-certificate configuration](../playwright.config.ts);
- [the strict sign-in assertion](../scripts/Assert-CbaSignInEvidence.ps1);
- [the transactional Conditional Access proof](../scripts/Invoke-ConditionalAccessProof.ps1).

The workflow must show `id-token: write`, the exact environment, a unique runner label, private DNS
verification, runtime Key Vault retrieval, PFX validation, Playwright execution, bounded evidence
and credential removal.

### 3. Execute the read-only verifier

```powershell
.\scripts\Show-E2eProof.ps1
```

The command must finish with:

```text
E2E_SHOWCASE_PASS
```

It creates ignored local files:

```text
.artifacts\showcase\e2e-proof.html
.artifacts\showcase\e2e-proof.json
```

Open the HTML report:

```powershell
Start-Process .\.artifacts\showcase\e2e-proof.html
```

### 4. Walk the report in order

1. **GitHub control plane:** exact repository, run, branch, commit, workflow and successful job.
2. **Job execution:** private DNS, OIDC exchange, Key Vault read, PFX validation, type-check,
   Playwright, bounded evidence and credential cleanup all passed.
3. **Receipt integrity:** local identity and network receipt SHA-256 values match the post-cleanup
   launcher journal.
4. **Identity:** the receipt matches the dedicated UPN, tenant and object ID held in ignored local
   state. Do not project the raw identifiers outside an approved internal audience.
5. **Network:** the in-run receipt observed the private runner address, exact Private Endpoint IP,
   immutable OIDC subject and successful Key Vault reads.
6. **Live Azure:** Key Vault still denies public access; Private Endpoint, DNS, runner subnet
   delegation and NAT are queried again.
7. **Conditional Access:** MFA CBA succeeded; SFA CBA failed with `500187`; both name the exact lab
   policy and use the modern PKI store.
8. **Restoration:** the policy is report-only and every isolated managed-policy baseline is
   restored.
9. **Cleanup:** the current Azure and GitHub APIs return zero matching ACI containers and zero
   matching runners.

### 5. Show the authenticated GitHub record without forcing browser SSO

```powershell
$run = Get-Content .\.lab-state\runner.json -Raw | ConvertFrom-Json
gh run view $run.workflowRunId `
  --repo $run.repository `
  --json status,conclusion,headSha,headBranch,url,jobs
```

Open the run URL only if the presenter is already authenticated to the intended GitHub account. If
the browser redirects to a different enterprise SSO tenant, stop; the CLI output and re-hashed
receipt remain the proof.

## Optional fresh cloud-runner proof

Use only after the workflow exists in the target repository and GitHub OIDC has been configured:

```powershell
$repository = '<github-owner>/<repository-name>' # Repository containing the solution on main.

.\scripts\Configure-GitHubOidc.ps1 `
  -Repository $repository `
  -AllowedBranches @('main')
.\scripts\Start-EphemeralGitHubRunner.ps1 `
  -Repository $repository `
  -Dispatch `
  -Ref main
$runnerProof = Get-Content .\.lab-state\runner.json -Raw | ConvertFrom-Json
$proofSetId = $runnerProof.proofSetId

.\scripts\Invoke-LocalFeasibility.ps1 -Headed -ProofSetId $proofSetId
.\scripts\Invoke-LocalFeasibility.ps1 -WrongOrigin -ProofSetId $proofSetId
.\scripts\Invoke-LocalFeasibility.ps1 -Repeat 5 -ProofSetId $proofSetId
.\scripts\Invoke-LocalFeasibility.ps1 -ReuseSession -ProofSetId $proofSetId
```

The launcher refuses to proceed unless local `HEAD` exactly equals the pushed branch head, Azure
and GitHub contexts match ignored state, the network topology is exact and the repository
permission is `ADMIN`.

## Optional fresh Conditional Access proof

Schedule an exclusive Conditional Access maintenance window. Use only the reviewed policy IDs for
the target tenant:

```powershell
$policyIds = @(
    '<managed-policy-id-1>',
    '<managed-policy-id-2>',
    '<managed-policy-id-3>'
) -join ','

.\scripts\Invoke-ConditionalAccessProof.ps1 `
  -TenantId '<tenant-id>' `
  -BrowserScenario Both `
  -InterferingPolicyIdsCsv $policyIds `
  -ConfirmExclusiveConditionalAccessWindow `
  -PropagationSeconds 900 `
  -NegativeFinalizationSeconds 120 `
  -EvidenceTimeoutMinutes 30

.\scripts\Show-E2eProof.ps1
```

The 57-minute token budget is checked before mutation. The lab policy is restored before long
evidence polling, the managed policies are restored in `finally`, and restoration failures are
reported alongside proof failures.

If interrupted:

```powershell
.\scripts\Invoke-ConditionalAccessProof.ps1 `
  -TenantId '<tenant-id>' `
  -InterferingPolicyIdsCsv $policyIds `
  -ConfirmExclusiveConditionalAccessWindow `
  -RestoreIsolationOnly
```

## Close with the production decision

The POC proves the security and automation pattern on an ephemeral ACI self-hosted runner. For
production, choose between:

- GitHub-hosted larger runners with Azure private networking when the required GitHub enterprise
  capability and billing are available; or
- an autoscaled ephemeral self-hosted runner platform with externalized diagnostics, strict
  workflow-author trust and one-job compute destruction.

Do not present Azure Private Link Service as a missing runner component. It would be relevant only
if the design also published an inbound service.
