# dev-agents-solutions
Here is where I build cool stuff.

## Guest Permissions Agent Solution (Azure + M365)

This repo now includes a shareable **Deploy to Azure** package for the Guest Permissions solution bootstrap.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsamitks77%2Fdev-agents-solutions%2Fmain%2Ftemplates%2Fazuredeploy%2Fguest-permissions-solution.json)

### What this deploys

- User-assigned managed identity
- Log Analytics workspace
- Storage account + Azure Files share
- Container Apps environment
- Azure Managed Grafana
- Optional RBAC grants for a Grafana operator principal (Reader + Log Analytics Reader)

### Package contents

- `templates/azuredeploy/guest-permissions-solution.json`
- `templates/azuredeploy/guest-permissions-solution.parameters.json`
- `docs/guest-permissions-deploy-to-azure.md`

### Next steps after infra bootstrap

1. Assign required Microsoft Graph app roles to the managed identity.
2. Deploy the guest-permissions pipeline runtime job (container image + job command).
3. Publish/import the Guest Permissions dashboard in Grafana.
4. Optionally provision/publish the M365 control-plane agent that triggers and monitors runs.

See full steps in: [`docs/guest-permissions-deploy-to-azure.md`](docs/guest-permissions-deploy-to-azure.md)
