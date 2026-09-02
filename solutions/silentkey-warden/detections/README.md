# Detection Library

Six KQL detections for Microsoft Entra **workload identities** (service principals and managed identities).

Five are deployed as Azure Monitor scheduled query alert rules by
[`../templates/azuredeploy/workload-identity-protection.json`](../templates/azuredeploy/workload-identity-protection.json).
The sixth is a hunting query you run by hand.

## The mapping that matters

Every detection here exists because a manual step in the POC guide proved the attack was possible.
The POC shows you the attack once; these detections watch for it forever.

| # | Detection | Proves out POC test | Alert rule | Severity | MITRE |
|---|---|---|---|---|---|
| [D1](D1-credential-added-to-application.kql) | Credential added to an application | **B** — Backdoor persistence | Yes | 2 — Warning | T1098.001 |
| [D2](D2-risky-workload-identity-detected.kql) | Risky workload identity detected (High/Medium) | **A** — Admin confirms compromised | Yes | 1 — Error | T1078 |
| [D3](D3-workload-identity-burst-signin.kql) | Multi-resource burst sign-in | **D** — Lateral movement burst | Yes | 2 — Warning | T1078, T1087 |
| [D4](D4-workload-identity-first-time-resource.kql) | First-time resource access | **C** — Anomalous Fabric access | Yes | 3 — Informational | T1078 |
| [D5](D5-workload-identity-blocked-by-ca.kql) | Blocked by Conditional Access (AADSTS53003) | **E** — CA enforcement | Yes | 2 — Warning | — |
| [D6](D6-report-only-enforcement-readiness.kql) | Report-only enforcement readiness | Step 8 — Verify CA decision | **No — hunting only** | — | — |

## Required tables

Nothing below produces a single row until Entra ID diagnostic settings are streaming into the
workspace. Run [`../scripts/configure-entra-diagnostics.ps1`](../scripts/configure-entra-diagnostics.ps1) first.

| Table | Diagnostic category | Used by |
|---|---|---|
| `AuditLogs` | `AuditLogs` | D1 |
| `AADServicePrincipalRiskEvents` | `ServicePrincipalRiskEvents` | D2 |
| `AADServicePrincipalSignInLogs` | `ServicePrincipalSignInLogs` | D3, D4, D5, D6 |
| `AADRiskyServicePrincipals` | `RiskyServicePrincipals` | Workbook |

## `ago()` and why the deployed rules do not use it

Each `.kql` file here is written for **interactive hunting**, so it opens with a `let Lookback = ...`
and filters on `TimeGenerated`.

The rules deployed by the ARM template deliberately **omit** that filter. Azure Monitor applies the
rule's own `windowSize` to the query automatically; adding a second time filter on top either
silently narrows the window or produces double-counting. The only exception is D4, whose 14-day
baseline subquery must reach further back than the rule window — that `ago()` is intentional.

## Deployment behaviour worth knowing

- **`skipQueryValidation` is set to `true` on every rule.** The Entra tables do not exist in a new
  workspace until logs start flowing, so pre-flight query validation would fail the deployment.
  This is expected and correct for this solution, not a shortcut.
- **D4 is noisy for its first 14 days.** The baseline is empty, so every resource looks new. Do not
  tune it before the window fills.
- **D3 has one knob**, `burstResourceThreshold` (default `4`). Sanctioned fan-out identities such as
  CSPM scanners or backup orchestrators should be excluded by AppId in `KnownFanOutApps` rather than
  by raising the threshold for everyone.

## Running one by hand

```bash
az monitor log-analytics query \
  --workspace "<workspace-customer-id>" \
  --analytics-query "$(cat detections/D2-risky-workload-identity-detected.kql)" \
  --output table
```

Or paste the file into **Log Analytics → Logs** in the portal.
