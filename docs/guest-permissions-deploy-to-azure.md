# Guest Permissions Solution — Deploy to Azure

This guide packages the Guest Permissions solution as a one-click Azure bootstrap.

## 1) One-click deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsamitks77%2Fdev-agents-solutions%2Fmain%2Ftemplates%2Fazuredeploy%2Fguest-permissions-solution.json)

Template file:

- `templates/azuredeploy/guest-permissions-solution.json`

Example parameter file:

- `templates/azuredeploy/guest-permissions-solution.parameters.json`

## 2) What the template deploys

1. User-assigned managed identity (runtime identity for collectors)
2. Log Analytics workspace (pipeline telemetry + query surface)
3. Storage account + Azure Files share (snapshot and artifact persistence)
4. Container Apps managed environment (job runtime host)
5. Azure Managed Grafana (dashboard host)
6. Optional RBAC grants for a provided operator object ID

## 3) Required post-deploy steps

The template intentionally bootstraps infrastructure only. You still need to complete runtime and identity permissions:

1. **Microsoft Graph permissions**
   - Assign required Graph app roles to the managed identity service principal (for Entra guest/user/group/role/PIM reads).
2. **Pipeline runtime deployment**
   - Build/push the guest-permissions runtime image.
   - Create/update Container Apps Job with environment variables and command sequence.
3. **Dashboard publication**
   - Configure Azure Monitor / Log Analytics datasource in Grafana.
   - Publish the guest-permissions dashboard JSON.
4. **M365 control-plane agent (optional)**
   - Provision and publish the M365 declarative agent to trigger and monitor runs.

## 4) Validation checklist

After deployment + post-deploy setup:

1. Container Apps Job exists and can run successfully.
2. Log Analytics contains pipeline telemetry rows (stage summaries, coverage, effective rows).
3. Grafana dashboard renders with live run metrics.
4. Effective snapshot artifacts are present in storage for the run.

## 5) Suggested structure for automation

To make this fully repeatable in CI/CD:

1. **Stage A**: ARM/Bicep infra deploy (this template)
2. **Stage B**: Identity grants (Graph app role assignments)
3. **Stage C**: Runtime deployment (job + image)
4. **Stage D**: Dashboard deployment (datasource + dashboard)
5. **Stage E**: Agent publish (optional M365 control plane)

This separation keeps infra idempotent and allows controlled approvals for privileged identity operations.
