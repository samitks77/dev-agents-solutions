# Guest Permissions Solution — Deploy to Azure (Enterprise Runbook)

This runbook explains every deployment phase in plain English:

- **What each step does**
- **Why that step matters**
- **How to validate success before moving on**

---

## 0) Prerequisites

### What this does

Confirms your operator machine and Azure permissions are ready.

### Why this matters

Most deployment failures happen before deployment starts (missing CLI, wrong subscription, insufficient RBAC).

### Requirements

- Azure subscription with rights to create resource groups and deploy resources
- Azure CLI (`az`) installed and authenticated
- PowerShell 7+ recommended
- Access to this repository

---

## 1) Validate the template and parameter file

### What this does

Checks JSON validity and required template/parameter structure before deployment.

### Why this matters

Catches fast-fail issues early, so you do not lose time debugging deployment runtime errors.

### Command

```powershell
.\scripts\validate-guest-permissions-bootstrap.ps1
```

---

## 2) Deploy infrastructure bootstrap

### What this does

Deploys baseline resources:

- User-assigned managed identity
- Log Analytics workspace
- Storage account + file share
- Container Apps managed environment
- Azure Managed Grafana
- Optional Grafana operator RBAC grants

### Why this matters

This creates the minimum enterprise platform layer required for secure operation and observability.

### Option A — Deploy button

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsamitks77%2Fdev-agents-solutions%2Fmain%2Ftemplates%2Fazuredeploy%2Fguest-permissions-solution.json)

### Option B — Scripted deployment (recommended for repeatability)

```powershell
.\scripts\deploy-guest-permissions-bootstrap.ps1 `
  -SubscriptionId "<subscription-guid>" `
  -ResourceGroupName "rg-guest-permissions" `
  -Location "eastus2"
```

---

## 3) Run post-deploy smoke tests

### What this does

Verifies that all required infrastructure resources are present and readable.

### Why this matters

Proves baseline health before you move to identity grants and runtime deployment.

### Command

```powershell
.\scripts\post-deploy-smoke-test.ps1 `
  -ResourceGroupName "rg-guest-permissions" `
  -ManagedIdentityName "mi-guest-permissions" `
  -LogAnalyticsWorkspaceName "law-guest-permissions" `
  -ContainerAppsEnvironmentName "cae-guest-permissions" `
  -GrafanaName "amg-guest-permissions" `
  -FileShareName "guest-permissions"
```

---

## 4) Apply required identity permissions (manual control gate)

### What this does

Assigns the Graph and Azure permissions needed by your runtime identity.

### Why this matters

Identity grants are high-impact changes and should be separated from infrastructure deployment for approval and audit.

### Typical grant categories

- Entra read permissions for guests/groups/roles/PIM schedules
- Azure RBAC read scopes for subscription/resource discovery
- Optional service data-plane read permissions where needed

> Use your internal least-privilege policy to finalize exact grants.

---

## 5) Deploy or connect the runtime collector

### What this does

Deploys the pipeline runtime (container/job) that collects and resolves guest permissions data.

### Why this matters

Without runtime execution, infrastructure is only a shell; no security evidence is produced.

### Inputs required from bootstrap outputs

- Managed identity client/principal IDs
- Log Analytics workspace ID
- Container Apps environment ID
- Storage account and share names

---

## 6) Publish dashboard and connect observability

### What this does

Configures Grafana data sources and imports/publishes dashboard(s).

### Why this matters

Turns raw telemetry into analyst-friendly insights and executive reporting.

---

## 7) Optional: publish M365 control-plane agent

### What this does

Adds an operator front-door where users can trigger runs and review statuses conversationally.

### Why this matters

Improves adoption and operational speed for both technical and non-technical operators.

---

## 8) Final validation before demo/customer handoff

### What this does

Confirms end-to-end pipeline success.

### Why this matters

Ensures confidence and credibility before internal or customer demos.

### Must-pass checks

1. Runtime executes successfully.
2. Telemetry lands in Log Analytics.
3. Dashboard renders live data.
4. Effective snapshot artifacts are generated.

---

## Reference files

- Template: `templates/azuredeploy/guest-permissions-solution.json`
- Parameters: `templates/azuredeploy/guest-permissions-solution.parameters.json`
- Template explanation: `templates/azuredeploy/guest-permissions-solution-explained.md`
- Operations guide: `docs/guest-permissions-operations-runbook.md`
- Security model: `docs/guest-permissions-security-governance.md`
