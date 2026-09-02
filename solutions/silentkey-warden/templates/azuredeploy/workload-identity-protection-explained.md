# Template Explained — Resource by Resource

Why each resource exists, what breaks without it, and the decisions that are easy to get wrong.

---

## 1. `Microsoft.OperationalInsights/workspaces`

**What:** the Log Analytics workspace that receives Entra ID audit, service principal sign-in, and
workload identity risk logs.

**Why:** Entra ID Protection shows you risk *right now* in the portal. It does not let you ask
"which identities got a new credential last quarter" or "did this identity ever touch Key Vault
before Tuesday." Detection and investigation both need history in a queryable store. That is this
workspace.

**Decisions worth understanding:**

| Setting | Value | Reasoning |
|---|---|---|
| `retentionInDays` | `90` | D4 compares against a **14-day** behavioural baseline. Anything under 30 days makes that detection meaningless, and incident investigation routinely reaches back a quarter. |
| `workspaceCapping.dailyQuotaGb` | `-1` (uncapped) | Safe default for a POC. In production, `ServicePrincipalSignInLogs` is usually the largest single category — set a real cap before enabling it tenant-wide. |
| `features.enableLogAccessUsingOnlyResourcePermissions` | `true` | Access is governed by Azure RBAC on the workspace rather than legacy workspace-level permissions. Fewer ways to accidentally over-grant. |
| `sku` | `PerGB2018` | Pay-as-you-go. Commitment tiers only make sense once you know real daily volume, which you will not until this has run for a week. |

---

## 2. `Microsoft.Insights/actionGroups`

**What:** the notification target every detection routes to.

**Why:** a detection with no action group fires into a void. The alert is recorded in Azure Monitor
and nobody finds out.

**Decisions worth understanding:**

- **The email receiver is optional.** If `socEmailAddress` is empty, the group deploys with no
  receivers. This keeps lab deployments clean and prevents a template from silently mailing an
  address someone copy-pasted from a sample file. The smoke test flags an empty group as a warning
  rather than a failure — it is a legitimate intermediate state, not a broken one.
- **`useCommonAlertSchema: true`.** The common schema is stable across alert types, so downstream
  SIEM or webhook integrations do not break when you add a different kind of alert later.
- **One group for all five detections.** Routing by severity belongs in the SIEM or the on-call tool,
  not in five near-identical action groups nobody maintains.

---

## 3. `Microsoft.Insights/scheduledQueryRules` × 5

**What:** detections D1–D5. Full KQL and triage guidance in
[`../../detections/README.md`](../../detections/README.md).

**Why:** this is the whole point of the solution. The POC guide proves five attacks are possible
against workload identities. These five rules watch for them continuously afterwards.

| Rule | Severity | Rationale for that severity |
|---|---|---|
| D1 — Credential added | 2 (Warning) | Legitimate rotations look identical at first glance. Needs a human, not a page. |
| D2 — Risky identity detected | 1 (Error) | Entra ID Protection already applied its confidence threshold. If this fires, something decided the identity is compromised. |
| D3 — Burst sign-in | 2 (Warning) | Strong signal, but sanctioned fan-out identities exist. Investigate, do not auto-contain. |
| D4 — First-time resource | 3 (Informational) | A lead, not a verdict. New integrations fire it legitimately. |
| D5 — Blocked by CA | 2 (Warning) | Cuts both ways: containment working, or a real workload broken. Both need eyes within minutes. |

**Decisions worth understanding:**

- **`skipQueryValidation: true` on every rule.** In a brand-new workspace, `AuditLogs` and
  `AADServicePrincipalSignInLogs` do not exist until Entra diagnostic settings start streaming.
  Server-side query validation would reject the query and fail the entire deployment. Since the
  template intentionally deploys *before* diagnostics are configured, validation must be skipped.
  The trade-off is that a genuine KQL typo would deploy silently — which is why the smoke test
  executes every detection against live data as a separate gate.
- **`windowSize` (1h) is larger than `evaluationFrequency` (15m) on purpose.** Entra log ingestion
  lags 15–30 minutes. Without overlapping windows, events that land late fall between evaluations
  and are never seen. The overlap costs a little duplicate processing and buys guaranteed coverage.
- **No `ago()` inside the rule queries.** Azure Monitor applies `windowSize` automatically. A second
  time filter either narrows the window unintentionally or double-counts. The one exception is D4,
  whose 14-day baseline subquery must deliberately reach past the rule window.
- **`autoMitigate: true`.** Alerts resolve themselves when the condition clears, so the SOC queue
  reflects current state rather than accumulating history.

---

## 4. `Microsoft.Insights/workbooks`

**What:** an Azure Monitor workbook with risk posture, credential change history, resource reach,
and Conditional Access outcomes.

**Why:** alerts tell you something happened. A workbook answers "what is the state of workload
identity risk in this tenant" — the question an architect or CISO actually asks, and the one you
need answered on a screen during a review.

**Decisions worth understanding:**

- **`serializedData` is built with the ARM `string()` function** over a structured variable rather
  than a hand-escaped JSON string. The workbook definition stays readable and diffable in source
  control instead of becoming an unmaintainable one-line blob.
- **The name is a deterministic `guid()`** derived from the resource group ID and name prefix.
  Workbook resource names must be GUIDs, and a deterministic one makes redeployment idempotent —
  you update the existing workbook instead of accumulating duplicates.
- **`sourceId` pins it to the workspace**, so it appears under that workspace's Workbooks blade
  where people will actually look for it.

---

## What the template deliberately does not do

| Not deployed | Why | Where it lives instead |
|---|---|---|
| Entra ID diagnostic settings | Tenant-scoped (`microsoft.aadiam`), not deployable from a resource group template | [`configure-entra-diagnostics.ps1`](../../scripts/configure-entra-diagnostics.ps1) |
| Conditional Access policy | Lives in Microsoft Graph, not Azure Resource Manager | [`deploy-conditional-access-policy.ps1`](../../scripts/deploy-conditional-access-policy.ps1) |
| POC test identities | Disposable demo artifacts, not infrastructure | [`invoke-poc-risk-simulation.ps1`](../../scripts/invoke-poc-risk-simulation.ps1) |

Separating tenant-wide privileged changes from resource deployment is not just a technical
constraint — those two things have different approvers and different rollback stories, and mixing
them into one deployment makes both harder to review.
