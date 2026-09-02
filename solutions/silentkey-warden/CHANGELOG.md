# Changelog

All notable changes to this solution are documented in this file.

## [1.0.0] - 2026-09-02

### Added

- Solution `README.md` with Deploy to Azure button, architecture and attack-sequence diagrams,
  POC-test-to-detection mapping, and documented limitations
- ARM template deploying the workload identity detection layer:
  - Log Analytics workspace with 90-day retention and resource-permission access model
  - SOC action group with optional email receiver
  - Five scheduled query alert rules (D1–D5)
  - Azure Monitor workbook for workload identity risk posture
- Detection library — six KQL queries mapped to POC tests and MITRE ATT&CK:
  - D1 credential added to an application (T1098.001)
  - D2 risky workload identity detected (High/Medium)
  - D3 multi-resource burst sign-in (T1078, T1087)
  - D4 first-time resource access
  - D5 blocked by Conditional Access (AADSTS53003)
  - D6 report-only enforcement readiness (hunting query, not deployed as an alert)
- Conditional Access policy definition and the evidence-based report-only to enforced path
- Seven commented PowerShell scripts: validate, deploy, configure Entra diagnostics, deploy CA
  policy, run the POC risk simulation, post-deploy smoke test, and cleanup
- Documentation set: index, architecture, deployment runbook, security and governance, operations
  runbook, demo playbook, and enterprise readiness checklist
- Interactive dark-mode POC guide (`docs/workload-identity-poc-guide.html`) covering 9 core steps
  and 5 risk simulation scenarios
- Template documentation with parameter/output reference and resource-by-resource rationale

### Design decisions recorded

- No runtime service principal or managed identity — automated containment would require an
  identity with tenant-wide denial-of-service capability
- Conditional Access defaults to report-only; enforcement is gated on D6 evidence
- `skipQueryValidation` enabled on all alert rules because Entra tables do not exist in a new
  workspace before diagnostic settings are configured
- Alert window (1h) deliberately four times the evaluation frequency (15m) to absorb Entra's
  15–30 minute log ingestion delay
