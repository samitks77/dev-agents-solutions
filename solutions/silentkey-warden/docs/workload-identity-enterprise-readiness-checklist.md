# Enterprise Readiness Checklist

Gate before calling this production-ready. Anything unchecked is a known gap, not an oversight.

## 1 — Prerequisites

- [ ] **Microsoft Entra Workload Identities Premium** licence confirmed in the target tenant
      (standalone SKU — not included in Entra ID P1 or P2)
- [ ] Deploying operator holds Contributor on the target resource group
- [ ] Security Administrator or Global Administrator available for the diagnostics step
- [ ] Conditional Access Administrator available for the policy step
- [ ] Target subscription and region agreed against data residency policy
- [ ] Azure CLI 2.50+ and PowerShell 7+ available

## 2 — Deployment

- [ ] `validate-workload-identity-bootstrap.ps1` passes with no failures
- [ ] What-If output reviewed and matches expectation (1 workspace, 1 action group, 5 rules, 1 workbook)
- [ ] Template deployed successfully
- [ ] Resource naming matches organisational standards (`namePrefix` set appropriately)
- [ ] Tags applied and align with the cost-attribution model
- [ ] Workspace retention set to 90 days or higher, or a documented exception exists
- [ ] `dailyQuotaGb` set to a real value in production, not `-1`

## 3 — Data collection

- [ ] Entra diagnostic settings configured
- [ ] All four required categories enabled: `AuditLogs`, `ServicePrincipalSignInLogs`,
      `RiskyServicePrincipals`, `ServicePrincipalRiskEvents`
- [ ] `ManagedIdentitySignInLogs` decision made and documented (enabled or explicitly out of scope)
- [ ] `AuditLogs` returning rows within the last hour
- [ ] `AADServicePrincipalSignInLogs` returning rows within the last hour
- [ ] First full day of ingestion volume measured and cost projected
- [ ] Daily cap validated as sufficient — a cap that is hit silently drops data

## 4 — Detections

- [ ] `post-deploy-smoke-test.ps1` passes with no FAIL rows
- [ ] All five alert rules deployed and enabled
- [ ] Each detection executed manually against live data and returns sane results
- [ ] Action group has at least one receiver, and it is a **monitored distribution list**, not an
      individual
- [ ] A test alert has been fired and receipt confirmed by the SOC
- [ ] `burstResourceThreshold` reviewed against the tenant's real fan-out identities
- [ ] Known-good fan-out identities added to `KnownFanOutApps` where applicable
- [ ] SIEM forwarding configured, or explicitly out of scope

## 5 — Conditional Access

- [ ] Policy created in **report-only** state
- [ ] Scope decision documented — pilot list or tenant-wide, and why
- [ ] Risk levels confirmed as High + Medium, with `low` excluded deliberately
- [ ] Policy has run in report-only for **at least 7 days**, covering a full weekend cycle
- [ ] D6 executed and `WouldHaveBlocked` reviewed
- [ ] Every identity in `WouldHaveBlocked` has a named owner and a documented decision
- [ ] Rollback procedure tested — enforced back to report-only, verified
- [ ] Enforcement change approved through change control

## 6 — Operations

- [ ] SOC triage procedure reviewed with the team that will run it
- [ ] Alert routing and on-call escalation path defined
- [ ] Incident response procedure walked through for at least one scenario
- [ ] Named owner assigned for the detection layer
- [ ] Named owner assigned for the Conditional Access policy
- [ ] Review cadence scheduled (weekly D6 while in report-only, monthly tuning, quarterly access)
- [ ] Runbook accessible to on-call staff outside this repository

## 7 — Validation

- [ ] `invoke-poc-risk-simulation.ps1` executed in a test tenant
- [ ] D1 confirmed firing on the backdoor credential scenario
- [ ] D2 confirmed firing on the admin-confirmed scenario
- [ ] D3 confirmed firing on the burst scenario
- [ ] D4 behaviour understood and its 14-day noise window accepted
- [ ] D5 confirmed firing when the policy is enforced
- [ ] End-to-end timing measured and documented for the local tenant
- [ ] `remove-poc-resources.ps1` executed and verified clean

## 8 — Governance

- [ ] Data collected and retention period reviewed against the compliance regime
- [ ] Workspace RBAC reviewed — least privilege, no legacy workspace permissions
- [ ] Holders of `IdentityRiskyServicePrincipal.ReadWrite.All` enumerated and approved
- [ ] Change control classification agreed per change type
- [ ] Audit trail verified for a deployment, a policy change, and a `confirmCompromised` call
- [ ] Threat model gaps reviewed and accepted by the security owner
- [ ] `Application.ReadWrite.All` confirmed **not** granted in production

## 9 — Handoff

- [ ] Architecture walkthrough delivered to the receiving team
- [ ] Operations runbook walkthrough delivered to the SOC
- [ ] Repository access granted to the operating team
- [ ] Support and escalation model agreed
- [ ] Known limitations formally communicated:
      - Workload Identities Premium licence dependency
      - ML detections need ~3 weeks of baseline in a new tenant
      - D4 noisy for its first 14 days
      - Sign-in log ingestion is the dominant cost
      - Containment is deliberately human-initiated, not automated

---

## Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Platform engineering | | | |
| Identity engineering | | | |
| Security operations | | | |
| Delivery lead | | | |
