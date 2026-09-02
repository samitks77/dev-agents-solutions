# Security and Governance

## Permission model

Every permission this solution needs, why it needs it, and when it is used. Nothing here holds
standing privilege to change identity state.

### Deployment-time permissions (human operator)

| Permission | Scope | Used by | Why |
|---|---|---|---|
| `Contributor` | Target resource group | ARM deployment | Create workspace, action group, alert rules, workbook |
| Security Administrator **or** Global Administrator | Tenant | `configure-entra-diagnostics.ps1` | Entra diagnostic settings are tenant-scoped |
| Conditional Access Administrator **or** Security Administrator | Tenant | `deploy-conditional-access-policy.ps1` | Create the CA policy |

### Runtime permissions

**None.** This is a deliberate design property.

The solution has no service principal, no managed identity, and no automation account with standing
access. Detections are Azure Monitor scheduled query rules that read a workspace the platform
already owns. Nothing in the deployed footprint can authenticate to Microsoft Graph or change the
state of any identity.

### Operator permissions (SOC, day 2)

| Permission | Scope | When |
|---|---|---|
| `Log Analytics Reader` | Workspace | Reading detections and the workbook — sufficient for most analysts |
| `IdentityRiskyServicePrincipal.ReadWrite.All` | Tenant | Only for analysts authorised to confirm or dismiss risk |
| `Application.ReadWrite.All` | Tenant | **POC simulation only.** Never grant this in production. |

## Least-privilege decisions

### Why there is no automation identity

The obvious design is a managed identity that reads risk events and calls `confirmCompromised`
automatically. That was rejected.

Such an identity needs `IdentityRiskyServicePrincipal.ReadWrite.All` — the ability to mark any
workload identity in the tenant as compromised and, with the CA policy enforced, deny it tokens
everywhere. That is a tenant-wide denial-of-service capability sitting in a secret.

The irony is not subtle: a solution that protects workload identities would have created the most
dangerous workload identity in the tenant.

Instead, containment is human-initiated. It is one API call, takes effect in 1–2 minutes, and leaves
a named actor in the audit log.

### Why the CA policy defaults to report-only

A blocked workload identity is a silent production outage. There is no user to call the help desk;
the failure surfaces as a batch job that stopped, or an API returning 401s to a customer.

The scripts enforce this. `deploy-conditional-access-policy.ps1` creates report-only unless
`-Enforce` is passed explicitly, and it refuses to run at all without an explicit scope decision.

### Why `low` risk is excluded from the policy

Low-risk detections are behavioural anomalies below the ML engine's medium-confidence threshold.
Including them trades a small detection gain for a large false-positive rate against identities with
no human to notice they broke.

## Data handling

### What is collected

| Data | Sensitivity | Retention |
|---|---|---|
| Service principal sign-in events | Identity telemetry — app IDs, resources, source IPs | 90 days default |
| Application audit events | Configuration changes and the actor who made them | 90 days default |
| Risk detections | Security findings per identity | 90 days default |
| Conditional Access decisions | Policy evaluation outcomes | 90 days default |

### What is not collected

- No credential material. Secrets never enter Log Analytics.
- No token contents or claims.
- No application payload or business data.
- No end-user personal data beyond the UPN of an admin who changed a configuration.

### Residency and access

- All data stays in the Log Analytics workspace, in the region chosen at deployment.
- Workspace access is governed by Azure RBAC. The template sets
  `enableLogAccessUsingOnlyResourcePermissions: true` so there is no legacy workspace-level
  permission path to over-grant through.
- Log export is one-way. Nothing in Azure Monitor can write back to the identity control plane.

### Retention rationale

The 90-day default is a floor, not a preference:

- D4 needs a **14-day** behavioural baseline to be meaningful at all
- Incident investigation routinely reaches back a quarter
- 30 days — the Log Analytics default — is not enough for either

If a compliance regime requires longer, raise `retentionInDays` or configure an archive tier. If
cost pressure demands shorter, drop `ServicePrincipalSignInLogs` volume with a daily cap rather than
cutting retention below 30 days.

## Auditability

Every privileged action in this solution is recorded, by design.

| Action | Audit location | Contains |
|---|---|---|
| ARM deployment | Azure Activity Log | Who deployed, when, what changed |
| Entra diagnostic setting change | Entra audit logs | Actor and modified categories |
| CA policy create or modify | Entra audit logs | Actor, before/after policy state |
| `confirmCompromised` | Entra audit logs + risk event record | Actor, target identity, timestamp |
| `dismiss` | Entra audit logs | Actor, target identity, timestamp |
| Alert rule change | Azure Activity Log | Actor and rule definition diff |

A useful property for an audit conversation: the same `AuditLogs` table that feeds detection D1 also
records changes to this solution's own configuration. It observes itself.

## Governance controls

### Change control

| Change | Blast radius | Suggested control |
|---|---|---|
| Deploy or update the template | Resource group only | Standard change |
| Modify a detection query | Detection coverage | Peer review; re-run the smoke test |
| Change CA policy **scope** | Which identities are evaluated | Change advisory board |
| Change CA policy **state** to enforced | **Tenant-wide, immediate** | CAB plus documented D6 evidence |
| Raise `burstResourceThreshold` | Reduced D3 sensitivity | Peer review; prefer `KnownFanOutApps` exclusions |

### Separation of duties

The solution deliberately splits into three deployment surfaces with different approvers:

1. **Azure resources** (ARM template) — platform engineering, resource-group scoped
2. **Tenant diagnostics** (`microsoft.aadiam`) — identity or security administration
3. **Conditional Access policy** (Microsoft Graph) — identity governance

No single script crosses all three. Someone with Contributor on a resource group cannot change
tenant-wide identity policy by running a deployment.

### Review cadence

| Activity | Frequency | Owner |
|---|---|---|
| Review D6 enforcement readiness | Weekly while in report-only | Identity engineering |
| Review D3 threshold and exclusions | Monthly | Detection engineering |
| Review workspace ingestion cost | Monthly | Platform engineering |
| Review who holds `IdentityRiskyServicePrincipal.ReadWrite.All` | Quarterly | Security governance |
| Re-run the enterprise readiness checklist | Quarterly | Delivery lead |

## Threat model — what this does not cover

Being explicit about the gaps is more useful than implying there are none.

| Not covered | Why | Compensating control |
|---|---|---|
| Federated credentials / workload identity federation | Different authentication path; no static secret to steal | Prefer federation over secrets; audit trust configurations separately |
| Certificate-based service principal auth | D1 detects certificate additions, but not private key theft | Certificate lifecycle management |
| Consent phishing | Different attack class targeting delegated permissions | Entra app consent policies and admin consent workflow |
| Over-permissioned but well-behaved identities | This detects anomalous *behaviour*, not excessive *entitlement* | Entitlement review; see also the `driftlock-vector` solution |
| Managed identity abuse from a compromised host | Token is legitimately issued to a legitimate identity | Host-level detection — Defender for Cloud |
| First 14 days of D4 | No baseline exists yet | Interim reliance on D2 and D3 |

## Secret handling in this repository

- No secrets are committed. The repository-level secret scanning workflow enforces this.
- `invoke-poc-risk-simulation.ps1` creates client secrets, holds them **in memory only**, and never
  writes them to disk or prints them.
- POC secrets default to a **7-day** lifetime.
- `remove-poc-resources.ps1` deletes the identities and the credentials with them.
