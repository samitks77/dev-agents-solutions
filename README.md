# Dev Agents Solutions

Enterprise-ready solution patterns for identity and access visibility across Entra + Azure.

This repo is organized as a collection of **self-contained solutions**. Each solution folder under `solutions/` holds everything needed to understand, deploy, and operate it — architecture docs, infra templates, scripts, and any agent surfaces — so nothing solution-specific lives at the repo root.

## Solutions

| Solution | Description |
|---|---|
| [`solutions/driftlock-vector/`](solutions/driftlock-vector/README.md) | **Guest Permissions Solution (Azure + M365).** Discovers guest users, resolves effective Entra + Azure access, and exposes it through Copilot Studio, Security Copilot, and an M365 Copilot declarative agent. Includes the Azure infra bootstrap (ARM templates, deploy/validate/smoke-test scripts), runbooks, and the declarative agent app package. |

See each solution's README for its own architecture diagram, deploy-to-Azure button, quick start, and repository map.

## Repository Map

```text
.
├── .github/workflows/
│   └── solution-quality.yml   # CI checks scoped to solutions/driftlock-vector
└── solutions/
    └── driftlock-vector/       # Guest Permissions Solution — fully self-contained
```
