# Security Policy

## Supported Scope

This folder contains deployment templates, KQL detections, a Conditional Access policy definition,
runbooks, and automation wrappers for the silentkey-warden Workload Identity Protection solution.

## Reporting a Vulnerability

If you discover a security issue in this solution:

1. Do not open a public issue with exploit details.
2. Report privately to the repository maintainers through your internal security process.
3. Include reproduction steps, affected files, and impact assessment.

## Security Expectations for Contributions

- Do not commit secrets (keys, tokens, client secrets, connection strings).
- Do not introduce a runtime identity with standing permission to modify identity state. The absence
  of one is a deliberate design property of this solution — see
  [`docs/workload-identity-security-governance.md`](docs/workload-identity-security-governance.md).
- Keep permission scopes least-privilege and documented.
- Keep infrastructure deployment separate from tenant-wide privileged operations. The three
  deployment surfaces (Azure resources, Entra diagnostics, Conditional Access policy) have different
  approvers on purpose.
- Any change that could cause a Conditional Access policy to be created in an enforced state must be
  explicit, opt-in, and documented.

## Operational Security Notes

- `invoke-poc-risk-simulation.ps1` creates real app registrations and client secrets. Run it in a
  test or demo tenant only. Secrets are held in memory, never written to disk or printed, and expire
  after 7 days by default.
- `Application.ReadWrite.All` is required for the simulation script only. It must never be granted
  in a production tenant.
- `IdentityRiskyServicePrincipal.ReadWrite.All` allows an operator to mark any workload identity in
  the tenant as compromised. With the Conditional Access policy enforced, that denies it tokens
  everywhere. Review holders of this permission quarterly.
