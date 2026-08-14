# guest-permissions-solution.json — Explained

ARM JSON templates do not support inline comments. This file documents **what each resource does** and **why it exists**.

## 1) Managed Identity

**Resource:** `Microsoft.ManagedIdentity/userAssignedIdentities`

- **What:** Creates a dedicated runtime identity.
- **Why:** Eliminates hardcoded credentials and supports least-privilege access design.

## 2) Log Analytics Workspace

**Resource:** `Microsoft.OperationalInsights/workspaces`

- **What:** Creates workspace for pipeline logs/telemetry.
- **Why:** Gives operations and security teams one place to monitor execution health and trends.

## 3) Storage Account + File Share

**Resources:**
- `Microsoft.Storage/storageAccounts`
- `Microsoft.Storage/storageAccounts/fileServices`
- `Microsoft.Storage/storageAccounts/fileServices/shares`

- **What:** Creates persistent storage for run artifacts/snapshots.
- **Why:** Preserves evidence and supports audit/comparison workflows.

## 4) Container Apps Managed Environment

**Resource:** `Microsoft.App/managedEnvironments`

- **What:** Creates runtime host environment and wires logs to Log Analytics.
- **Why:** Enables scheduled/on-demand jobs with centralized observability.

## 5) Azure Managed Grafana

**Resource:** `Microsoft.Dashboard/grafana`

- **What:** Creates dashboard platform.
- **Why:** Provides an enterprise visualization layer over telemetry and findings.

## 6) Optional Role Assignments

**Resources:** `Microsoft.Authorization/roleAssignments` (conditional)

- **What:** Grants Reader on Grafana and Log Analytics Reader on workspace to provided operator object ID.
- **Why:** Enables controlled access for viewers/operators without broad owner permissions.

## 7) Outputs

The template returns identity IDs, workspace ID, environment ID, storage name, and Grafana endpoint.

- **What:** Machine-readable deployment outputs.
- **Why:** Supports deterministic automation for downstream runtime and dashboard setup.
