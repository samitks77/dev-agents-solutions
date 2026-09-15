# Dev Agents Solutions

Enterprise-ready solution patterns for identity and access visibility across Entra + Azure.

This repo is organized as a collection of **self-contained solutions**. Each solution folder under `solutions/` holds everything needed to understand, deploy, and operate it — architecture docs, infra templates, scripts, and any agent surfaces — so nothing solution-specific lives at the repo root.

## Solutions

| Solution | Description |
|---|---|
| [`solutions/driftlock-vector/`](solutions/driftlock-vector/README.md) | **Guest Permissions Solution (Azure + M365).** Discovers guest users, resolves effective Entra + Azure access, and exposes it through Copilot Studio, Security Copilot, and an M365 Copilot declarative agent. Includes the Azure infra bootstrap (ARM templates, deploy/validate/smoke-test scripts), runbooks, and the declarative agent app package. |
| [`solutions/entra-cba-playwright/`](solutions/entra-cba-playwright/README.md) | **Verified Playwright authentication (GitHub Actions + Azure + Entra CBA).** Runs unattended browser tests from a one-job Azure runner with deterministic egress, private Key Vault certificate retrieval, GitHub OIDC, exact identity assertions, Conditional Access authentication-strength proof, bounded evidence, and verified cleanup. |
| [`solutions/silentkey-warden/`](solutions/silentkey-warden/README.md) | **Workload Identity Protection (Entra + Azure Monitor).** Brings adaptive protection to service principals and managed identities. Turns the five manual Workload Identity Protection POC tests into standing production detections: an ARM-deployed Log Analytics workspace, six KQL detections mapped to MITRE, an Azure Monitor workbook, a report-only Conditional Access policy, an end-to-end risk simulation script, and an interactive POC guide. |

The two solutions are complementary. `driftlock-vector` answers **what an identity is entitled to
do**; `silentkey-warden` answers **what it just did**.

See each solution's README for its architecture, deployment entry point, quick start, and repository map.

## Repository Map

```text
.
├── .github/workflows/
│   └── solution-quality.yml   # CI checks across every solution under solutions/
└── solutions/
    ├── driftlock-vector/       # Guest Permissions Solution — fully self-contained
    ├── entra-cba-playwright/   # Verified Playwright authentication — GitHub, Azure, Entra CBA
    └── silentkey-warden/       # Workload Identity Protection — fully self-contained
```
