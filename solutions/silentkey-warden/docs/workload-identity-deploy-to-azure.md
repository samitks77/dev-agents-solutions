# Deployment Runbook

End-to-end deployment with the reasoning behind each step. Budget **45 minutes** of hands-on time,
plus a 30-minute wait for the first logs to land.

> All commands assume you have `cd`'d into `solutions/silentkey-warden/`.

---

## Before you start

### Licensing — check this first

**Microsoft Entra Workload Identities Premium** is a standalone SKU. It is **not** included in
Entra ID P1 or P2, and this is the single most common reason a POC stalls on day one.

Verify at: **Entra admin center → Billing → Licenses → All products** → look for
`Workload Identities Premium`.

Without it:

- The **Risky workload identities** blade is unavailable
- The Conditional Access **service principal risk** condition cannot be configured
- `AADServicePrincipalRiskEvents` never populates, so detection D2 stays permanently empty

Everything else in this solution — log collection, D1, D3, D4, D5, the workbook — works without it.
If licensing is blocked, deploy anyway and enable D2 later.

### Roles and permissions

| Step | Required role |
|---|---|
| Deploy the ARM template | Contributor on the target resource group |
| Configure Entra diagnostics | Security Administrator or Global Administrator |
| Create the Conditional Access policy | Conditional Access Administrator, Security Administrator, or Global Administrator |
| Run the POC simulation | Application Administrator + Security Administrator (or Global Administrator) |

### Tooling

- Azure CLI 2.50 or later — `az version`
- PowerShell 7 or later — `$PSVersionTable.PSVersion`
- An Azure subscription you can create resources in

---

## Step 1 — Validate before you deploy

**What:** parses the template locally, confirms the detection library is intact, then runs ARM
validation and What-If against Azure.

**Why:** a deployment that fails halfway leaves partial resources behind. Validation is free.

```powershell
# Local-only, no Azure session required
./scripts/validate-workload-identity-bootstrap.ps1 -SkipAzureChecks

# Full preflight
./scripts/validate-workload-identity-bootstrap.ps1 `
  -SubscriptionId <sub> `
  -ResourceGroupName rg-silentkey-warden `
  -Location eastus2
```

Read the What-If output. You should see one workspace, one action group, five scheduled query rules,
and one workbook.

---

## Step 2 — Deploy the detection layer

**What:** creates the Log Analytics workspace, SOC action group, five detection rules, and the
workbook.

**Why:** the workspace has to exist before Entra has anywhere to stream logs to. This is the
foundation everything else attaches to.

```powershell
./scripts/deploy-workload-identity-bootstrap.ps1 `
  -SubscriptionId <sub> `
  -ResourceGroupName rg-silentkey-warden `
  -Location eastus2 `
  -SocEmailAddress soc@contoso.com
```

Or use the **Deploy to Azure** button in the [solution README](../README.md).

Save the `logAnalyticsWorkspaceResourceId` output — the next step needs it.

> **Expected:** the detections deploy successfully and return nothing. They are blind until Step 3.

---

## Step 3 — Stream Entra logs into the workspace

**What:** creates a tenant-level diagnostic setting forwarding Entra audit, service principal
sign-in, and workload identity risk logs.

**Why:** this is the step everyone forgets, and the reason a correctly deployed detection layer
reports nothing. Entra diagnostic settings are tenant-scoped (`microsoft.aadiam`) and cannot be
created by a resource-group ARM template.

```powershell
./scripts/configure-entra-diagnostics.ps1 `
  -WorkspaceResourceId "<logAnalyticsWorkspaceResourceId from Step 2>"
```

Categories enabled and what each one feeds:

| Category | Feeds |
|---|---|
| `AuditLogs` | D1 — credential additions |
| `ServicePrincipalSignInLogs` | D3, D4, D5, D6 — all token telemetry |
| `RiskyServicePrincipals` | Workbook — current risk state |
| `ServicePrincipalRiskEvents` | D2 — individual risk detections |
| `ManagedIdentitySignInLogs` | Optional, `-IncludeManagedIdentitySignInLogs` |

> **Cost warning.** `ServicePrincipalSignInLogs` is usually the highest-volume category in a large
> tenant. Set `dailyQuotaGb` on the workspace before enabling it in production, and review actual
> ingestion after the first full day.

**Now wait 15–30 minutes.** Nothing below will show data before then.

---

## Step 4 — Create the Conditional Access policy

**What:** creates the workload identity CA policy in **report-only** mode.

**Why:** report-only logs the decision without blocking the sign-in. A blocking policy on workload
identities can take down production integrations instantly, and the affected identities are usually
the ones with no owner.

```powershell
# Pilot scope - recommended first
./scripts/deploy-conditional-access-policy.ps1 `
  -ServicePrincipalIds @("<sp-object-id-1>", "<sp-object-id-2>")

# Tenant-wide scope - the production end state
./scripts/deploy-conditional-access-policy.ps1 -ScopeAllServicePrincipals
```

The script refuses to run without an explicit scope decision. That is intentional — it will not
guess the blast radius of a blocking policy.

Design rationale: [`../policies/README.md`](../policies/README.md).

---

## Step 5 — Verify the deployment

**What:** confirms resources exist, tables are populating, and detections execute against real data.

**Why:** a detection layer receiving no data looks identical to a working one, right up until an
incident.

```powershell
./scripts/post-deploy-smoke-test.ps1 `
  -SubscriptionId <sub> `
  -ResourceGroupName rg-silentkey-warden
```

Reading the output:

| Result | Meaning |
|---|---|
| All PASS | Deployed and receiving data |
| WARN on table checks | Normal within the first hour after Step 3. Re-run later. |
| WARN on action group | Deployed with no receivers — alerts fire silently. Add a receiver. |
| Any FAIL | Stop and resolve before continuing |

---

## Step 6 — Prove it works

**What:** creates four disposable test identities and drives the five risk scenarios end to end.

**Why:** confirms the whole chain — signal, detection, notification — before you rely on it, and it
is the demo.

> **Run this in a test or demo tenant.** It creates real identities and raises real risk events.

```powershell
# See what it would do
./scripts/invoke-poc-risk-simulation.ps1 -WhatIf

# Run it
./scripts/invoke-poc-risk-simulation.ps1
```

Expected timeline after the run:

| When | What appears |
|---|---|
| 1–2 min | Identities in **Protection → Identity Protection → Risky workload identities** at High risk |
| 15–20 min | D1 returns the backdoor credential addition |
| 15–30 min | D2, D3, D4 return rows; service principal sign-ins visible in the portal |
| Next evaluation | Alerts fire to the action group |

Manual walkthrough of the same scenarios: [`workload-identity-poc-guide.html`](workload-identity-poc-guide.html).

---

## Step 7 — Move to enforcement

Only after the policy has run in report-only for **at least 7 days**, so it has seen a full weekly
cycle including weekend batch jobs.

1. Run [`../detections/D6-report-only-enforcement-readiness.kql`](../detections/D6-report-only-enforcement-readiness.kql)
2. Read `WouldHaveBlocked`:
   - **Zero** → enforcing is safe
   - **Non-zero** → every identity listed needs an owner and an explanation first
3. Enforce:

   ```bash
   az rest --method patch \
     --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>" \
     --body '{"state":"enabled"}' \
     --headers "Content-Type=application/json"
   ```

4. Watch D5 closely for 24 hours.

Rollback is instant and needs no application change — patch `state` back to
`enabledForReportingButNotEnforced`.

---

## Step 8 — Clean up the POC identities

```powershell
./scripts/remove-poc-resources.ps1
```

Removes the test identities and dismisses their risk. Deliberately leaves the CA policy and the
Azure detection layer in place — those are the parts worth keeping.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Detections return nothing | Diagnostic settings not configured | Run Step 3 |
| Tables exist but are empty | Less than 30 min since Step 3 | Wait, then re-run the smoke test |
| D2 permanently empty | Missing Workload Identities Premium license | Verify licensing; other detections still work |
| D4 extremely noisy | Baseline still filling | Expected for 14 days. Do not tune it down yet. |
| Alerts fire but nobody is notified | Action group has no receivers | Add one, or redeploy with `-SocEmailAddress` |
| Deployment fails on query validation | `skipQueryValidation` was removed | Restore it — Entra tables do not exist in a new workspace |
| `confirmCompromised` returns 403 | Missing Graph consent | Consent to `IdentityRiskyServicePrincipal.ReadWrite.All` |
| CA policy creation fails | Missing licence or role | Verify Workload Identities Premium and CA Administrator |
| Simulation sign-ins fail immediately | Directory replication lag | Wait 60 seconds and retry — the script already waits 30 |
