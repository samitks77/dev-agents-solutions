# Documentation Index

Everything needed to understand, deploy, operate, and demo the silentkey-warden Workload Identity
Protection solution.

| Document | Purpose | Audience |
|---|---|---|
| [`workload-identity-poc-guide.html`](workload-identity-poc-guide.html) | Interactive step-by-step POC guide — 9 core steps plus 5 risk simulation scenarios | Architects, technical sellers, security engineers |
| [`workload-identity-architecture.md`](workload-identity-architecture.md) | End-to-end architecture, data flow, and trust boundaries | Architects, security leads |
| [`workload-identity-deploy-to-azure.md`](workload-identity-deploy-to-azure.md) | Full deployment runbook with what/why at every step | Platform engineers, cloud admins |
| [`../detections/README.md`](../detections/README.md) | The detection library — 6 KQL queries mapped to POC tests and MITRE | Detection engineers, SOC |
| [`../policies/README.md`](../policies/README.md) | Conditional Access policy design and the report-only to enforced path | Identity engineers, security admins |
| [`workload-identity-security-governance.md`](workload-identity-security-governance.md) | Permission model, least privilege, and governance controls | Security engineering, compliance |
| [`workload-identity-operations-runbook.md`](workload-identity-operations-runbook.md) | Day-2 operations, alert triage, incident response, troubleshooting | SOC operators, operations teams |
| [`workload-identity-demo-playbook.md`](workload-identity-demo-playbook.md) | 30-minute demo talk-track and sequence | Technical sellers, architects |
| [`workload-identity-enterprise-readiness-checklist.md`](workload-identity-enterprise-readiness-checklist.md) | Go-live quality gates | Delivery leads, project managers |

## Recommended reading order

**If you are evaluating the idea:**

1. [POC guide](workload-identity-poc-guide.html) — open in a browser, it is a self-contained dark-mode artifact
2. [Architecture](workload-identity-architecture.md)
3. [Demo playbook](workload-identity-demo-playbook.md)

**If you are deploying it:**

1. [Architecture](workload-identity-architecture.md)
2. [Deployment runbook](workload-identity-deploy-to-azure.md)
3. [Security and governance](workload-identity-security-governance.md)
4. [Detection library](../detections/README.md)
5. [Conditional Access policy](../policies/README.md)
6. [Enterprise readiness checklist](workload-identity-enterprise-readiness-checklist.md)

**If you are running it:**

1. [Operations runbook](workload-identity-operations-runbook.md)
2. [Detection library](../detections/README.md) — triage guidance is inline in each `.kql` file

## The one thing to remember

The POC proves five attacks against workload identities are possible. The detection layer makes
sure you find out the next time they happen. Do not stop at the POC.
