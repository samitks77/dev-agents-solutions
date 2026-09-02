# Azure Deploy Template Guide

## Files

- `workload-identity-protection.json` — main ARM template
- `workload-identity-protection.parameters.json` — sample parameter values
- `workload-identity-protection-explained.md` — resource-by-resource rationale

## What gets deployed

| Resource | Count | Purpose |
|---|---|---|
| `Microsoft.OperationalInsights/workspaces` | 1 | Destination for Entra audit, sign-in, and risk logs |
| `Microsoft.Insights/actionGroups` | 1 | SOC notification target for all five detections |
| `Microsoft.Insights/scheduledQueryRules` | 5 | The detections D1–D5 |
| `Microsoft.Insights/workbooks` | 1 | Workload Identity Protection dashboard |

## Deploy options

### Option 1 — Deploy to Azure button

Use the button in the solution's [`README.md`](../../README.md).

### Option 2 — Wrapper script (recommended)

```powershell
./scripts/deploy-workload-identity-bootstrap.ps1 `
  -SubscriptionId <sub> `
  -ResourceGroupName rg-silentkey-warden `
  -Location eastus2 `
  -SocEmailAddress soc@contoso.com
```

### Option 3 — Azure CLI

```bash
az deployment group create \
  --resource-group rg-silentkey-warden \
  --template-file templates/azuredeploy/workload-identity-protection.json \
  --parameters @templates/azuredeploy/workload-identity-protection.parameters.json
```

## Parameter reference

| Parameter | What it controls | Why it exists |
|---|---|---|
| `location` | Deployment region | Keeps resources region-aligned for latency and data residency policy |
| `namePrefix` | Prefix on every resource name | Makes the solution identifiable in a shared subscription and keeps alert rule names sortable |
| `logAnalyticsWorkspaceName` | Workspace name | Deterministic reference for the diagnostic settings step that follows |
| `retentionInDays` | Workspace retention (default `90`) | D4 needs a 14-day behavioural baseline; 90 days gives investigation headroom without over-paying |
| `dailyQuotaGb` | Ingestion cap, `-1` for uncapped | `ServicePrincipalSignInLogs` is high-volume in large tenants — this is the cost guardrail |
| `socEmailAddress` | Action group email receiver | Optional, so the template deploys cleanly in labs with no distribution list |
| `deployAlertRules` | Deploy D1–D5 (default `true`) | Lets you stand the workspace up first and add detections once logs are flowing |
| `deployWorkbook` | Deploy the workbook (default `true`) | Some customers standardise on Grafana or Sentinel workbooks instead |
| `alertEvaluationFrequency` | How often detections run (default `PT15M`) | Trades detection latency against query cost |
| `alertWindowSize` | Lookback per evaluation (default `PT1H`) | Overlap absorbs Entra's 15–30 minute log ingestion delay so events are not missed |
| `burstResourceThreshold` | Distinct resources before D3 fires (default `4`) | The single tuning knob for the lateral movement detection |
| `tagValues` | Tags on every resource | Cost attribution and inventory |

## Outputs reference

| Output | Why you need it |
|---|---|
| `logAnalyticsWorkspaceName` | Referenced by the smoke test |
| `logAnalyticsWorkspaceResourceId` | Required input to `configure-entra-diagnostics.ps1` |
| `logAnalyticsCustomerId` | Required to run KQL via `az monitor log-analytics query` |
| `actionGroupResourceId` | Wiring additional receivers or reusing the group elsewhere |
| `alertRulesDeployed` | Quick confirmation that detections were included |
| `workbookResourceId` | Direct portal link to the dashboard |
| `nextStepConfigureEntraDiagnostics` | The exact command for the step everyone forgets |

## Validation guidance

Commands below assume you are in `solutions/silentkey-warden/`.

1. Local-only checks, no Azure session needed:

   ```powershell
   ./scripts/validate-workload-identity-bootstrap.ps1 -SkipAzureChecks
   ```

2. Full preflight including ARM validation and What-If:

   ```powershell
   ./scripts/validate-workload-identity-bootstrap.ps1 -SubscriptionId <sub> -ResourceGroupName rg-silentkey-warden -Location eastus2
   ```

3. Confirm parameter values match your naming standards.
4. Confirm the SOC address is a monitored distribution list, not an individual.

## Known behaviours that are intentional

- **`skipQueryValidation: true` on all five rules.** The Entra tables do not exist in a new
  workspace until logs flow. Server-side query validation would fail the deployment. This is
  correct for this solution.
- **Deployment succeeds but detections return nothing.** Expected until
  `configure-entra-diagnostics.ps1` runs. The template output says so explicitly.
- **D4 is noisy for 14 days.** Its baseline is empty at first. Do not tune it before it fills.
