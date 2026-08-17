# Azure Deploy Template Guide

## Files

- `guest-permissions-solution.json` — main ARM template
- `guest-permissions-solution.parameters.json` — sample parameter values
- `guest-permissions-solution-explained.md` — detailed explanation of each resource

## Deploy Options

### Option 1: Deploy to Azure button

Use the button in the solution's [`README.md`](../../README.md).

### Option 2: Azure CLI

```bash
az deployment group create \
  --resource-group rg-guest-permissions \
  --template-file templates/azuredeploy/guest-permissions-solution.json \
  --parameters @templates/azuredeploy/guest-permissions-solution.parameters.json
```

## Parameter Reference

| Parameter | What it controls | Why it exists |
|---|---|---|
| `location` | Deployment region | Keeps all resources region-aligned for latency and policy consistency |
| `managedIdentityName` | Runtime identity name | Allows deterministic identity references during runtime configuration |
| `logAnalyticsWorkspaceName` | Log workspace name | Centralizes pipeline telemetry and troubleshooting data |
| `containerAppsEnvironmentName` | Container Apps env name | Defines runtime host boundary for job execution |
| `grafanaName` | Managed Grafana name | Provides dashboard endpoint for operational visibility |
| `fileShareName` | Azure Files share name | Persists run snapshots/evidence for audit and diff analysis |
| `grafanaOperatorObjectId` | Optional operator principal | Enables controlled dashboard/operator access grants |

## Outputs Reference

| Output | Why you need it |
|---|---|
| `managedIdentityClientId` | Runtime configuration and identity wiring |
| `managedIdentityPrincipalId` | RBAC and permission assignment workflows |
| `logAnalyticsWorkspaceId` | Dashboard datasource and telemetry wiring |
| `containerAppsEnvironmentId` | Runtime deployment targeting |
| `storageAccountName` | Snapshot persistence wiring |
| `fileShareName` | Snapshot path construction |
| `grafanaName` | Dashboard publishing automation |
| `grafanaEndpoint` | Operator and demo endpoint |

## Validation Guidance

Before deploying (commands below assume you're in `solutions/driftlock-vector/`):

1. Run `scripts/validate-guest-permissions-bootstrap.ps1`
2. Confirm parameter values for your environment naming standards
3. Confirm RBAC scope and approval for operator identity
