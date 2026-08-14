# Guest Permissions Solution — Operations Runbook

## 1) Run Modes

### Manual run mode

**What it does**

- Operator triggers collection/resolution when needed.

**Why it matters**

- Ideal for validation, incident support, and controlled demos.

### Scheduled mode

**What it does**

- Executes collection on a defined cadence (for example daily).

**Why it matters**

- Produces consistent governance evidence and trend visibility.

### Agent-triggered mode (optional)

**What it does**

- M365 agent calls control-plane actions for run orchestration.

**Why it matters**

- Improves operational speed and user experience for analysts.

---

## 2) Daily / Weekly Operations

### Daily checks

1. Confirm latest run status is successful.
2. Confirm telemetry ingestion to Log Analytics.
3. Confirm dashboard freshness.

### Weekly checks

1. Review failed runs and root causes.
2. Review high-risk guest access findings.
3. Verify no permission drift in runtime identity grants.

---

## 3) Monitoring Signals

Track at minimum:

- Run success/failure rate
- Stage duration trend
- Coverage rates (resources scanned vs total expected)
- Effective permission row volume trend

---

## 4) Incident Handling

| Scenario | Immediate action | Recovery action |
|---|---|---|
| Runtime failed to authenticate | Check managed identity and grants | Re-apply missing grants; rerun |
| Collection partial/empty | Check API quota/errors and scope | Retry with narrowed scope; then full run |
| Dashboard blank | Validate datasource/workspace and query timeframe | Fix datasource binding and refresh |
| Unexpected permission spike | Validate source run and compare prior snapshots | Escalate to IAM governance workflow |

---

## 5) Change Management

Any production change should include:

1. Planned change summary
2. Pre-change validation
3. Rollback path
4. Post-change smoke test result

---

## 6) Operational Commands

### Validate template package

```powershell
.\scripts\validate-guest-permissions-bootstrap.ps1
```

### Deploy/update bootstrap

```powershell
.\scripts\deploy-guest-permissions-bootstrap.ps1 `
  -SubscriptionId "<subscription-guid>" `
  -ResourceGroupName "rg-guest-permissions" `
  -Location "eastus2"
```

### Post-deploy health check

```powershell
.\scripts\post-deploy-smoke-test.ps1 `
  -ResourceGroupName "rg-guest-permissions" `
  -ManagedIdentityName "mi-guest-permissions" `
  -LogAnalyticsWorkspaceName "law-guest-permissions" `
  -ContainerAppsEnvironmentName "cae-guest-permissions" `
  -GrafanaName "amg-guest-permissions" `
  -FileShareName "guest-permissions"
```
