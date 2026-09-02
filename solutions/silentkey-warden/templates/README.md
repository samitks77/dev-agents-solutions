# Templates

Infrastructure as code for the silentkey-warden Workload Identity Protection solution.

| Path | Contents |
|---|---|
| [`azuredeploy/`](azuredeploy/README.md) | ARM template, sample parameters, and a resource-by-resource explanation |

The template deploys the **detection layer only** — a Log Analytics workspace, an SOC action group,
five scheduled query alert rules, and a workbook.

Two things it deliberately does not deploy, because neither is a resource-group-scoped resource:

- **Entra ID diagnostic settings** are tenant-scoped (`microsoft.aadiam`). Configured by
  [`../scripts/configure-entra-diagnostics.ps1`](../scripts/configure-entra-diagnostics.ps1).
- **The Conditional Access policy** lives in Microsoft Graph. Created by
  [`../scripts/deploy-conditional-access-policy.ps1`](../scripts/deploy-conditional-access-policy.ps1).

That separation is deliberate: infrastructure deployment and tenant-wide privileged policy changes
have different blast radii, different approvers, and usually different change windows.
