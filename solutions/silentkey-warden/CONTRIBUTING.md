# Contributing

Thanks for contributing to this solution package.

## Contribution Standards

1. Keep runbooks in plain English.
2. For every operational step, include:
   - **What it does**
   - **Why it matters**
3. Prefer idempotent scripts and explicit validation checks.
4. Never hardcode secrets or tenant-specific credentials.

## Detection-specific standards

Detections are the product here, so they carry extra requirements.

1. Every `.kql` file opens with a header comment stating:
   - Which POC test or attack behaviour it covers
   - The source table and diagnostic category
   - Severity and MITRE technique
   - What it finds, why it matters, and how to triage a hit
2. State the false-positive profile honestly. If a detection is noisy for its first two weeks, say
   so in the file, not only in the docs.
3. Standalone `.kql` files use an explicit `let Lookback = ...` for interactive hunting. Queries
   embedded in alert rules must **not** filter on `TimeGenerated` — Azure Monitor applies
   `windowSize` automatically. Document any deliberate exception (D4's baseline is the current one).
4. Prefer an explicit exclusion list over loosening a threshold. Raising a threshold reduces
   sensitivity for everyone; an exclusion is scoped and reviewable.
5. New detections must be added to `detections/README.md` and, if deployed, to the ARM template and
   the smoke test's expected rule count.

## Pull Request Checklist

- [ ] Documentation updated for behavioral changes
- [ ] Deployment/validation scripts updated if needed
- [ ] JSON and PowerShell checks pass in GitHub Actions
- [ ] New or changed KQL executed against real data, not just parsed
- [ ] Security/governance impact reviewed
- [ ] No new standing permissions introduced without explicit justification

## Commit Guidance

Use clear, outcome-oriented commit messages (what changed + why).
