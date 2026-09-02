# Conditional Access Policy

The control that turns a risk *signal* into a risk *decision*.

## `ca-block-risky-workload-identities.json`

A Microsoft Graph request body for a workload identity Conditional Access policy. Deploy it with
[`../scripts/deploy-conditional-access-policy.ps1`](../scripts/deploy-conditional-access-policy.ps1),
which is preferred over pasting this by hand because it refuses to create a blocking policy
without an explicit scope decision.

## What each block does

| Element | Value | Why |
|---|---|---|
| `state` | `enabledForReportingButNotEnforced` | Report-only. Logs the decision, blocks nothing. This is the only safe starting state. |
| `conditions.clientApplications.includeServicePrincipals` | `ServicePrincipalsInMyTenant` | Every service principal in the tenant. Replace with explicit object IDs to pilot narrowly first. |
| `conditions.applications.includeApplications` | `All` | The policy evaluates at token issuance, so it covers every resource — ARM, Key Vault, SQL, Storage, Fabric, Graph. |
| `conditions.servicePrincipalRiskLevels` | `high`, `medium` | High catches admin-confirmed compromise and leaked credentials. Medium catches ML-detected anomalies before they escalate. Low is excluded deliberately. |
| `grantControls.builtInControls` | `block` | There is no MFA fallback for a workload identity. Block is the only meaningful control. |

## Why `low` is excluded

Low-risk detections are minor behavioural anomalies below the ML engine's medium-confidence
threshold. Including them trades a small detection gain for a large false-positive rate against
identities that have no human to notice they broke. Every blocked workload identity is a silent
production outage until someone reads a log.

## The report-only to enforced path

Do not skip a step here.

1. Deploy in report-only. **Default. No impact.**
2. Wait at least 7 days so the policy sees a full weekly cycle, including weekend batch jobs.
3. Run [`../detections/D6-report-only-enforcement-readiness.kql`](../detections/D6-report-only-enforcement-readiness.kql).
4. Read `WouldHaveBlocked`. Zero means enforcing is safe. Non-zero means every identity listed
   needs an owner and an explanation *before* you continue.
5. Enforce:

   ```bash
   az rest --method patch \
     --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>" \
     --body '{"state":"enabled"}' \
     --headers "Content-Type=application/json"
   ```

6. Watch [`../detections/D5-workload-identity-blocked-by-ca.kql`](../detections/D5-workload-identity-blocked-by-ca.kql)
   closely for the first 24 hours.

## Rolling back

Enforced to report-only is instant and requires no application changes:

```bash
az rest --method patch \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>" \
  --body '{"state":"enabledForReportingButNotEnforced"}' \
  --headers "Content-Type=application/json"
```

To restore a single identity instead, dismiss its risk in Identity Protection. No secret rotation
is needed if it was never actually compromised.

## Prerequisites

- **Microsoft Entra Workload Identities Premium** — a standalone SKU, not part of Entra ID P2.
  Without it the `servicePrincipalRiskLevels` condition is unavailable.
- `Policy.ReadWrite.ConditionalAccess` and `Application.Read.All`
- Conditional Access Administrator, Security Administrator, or Global Administrator
