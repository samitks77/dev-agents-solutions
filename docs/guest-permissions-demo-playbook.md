# Guest Permissions Solution — Demo Playbook

This playbook is structured for two audiences:

1. **Internal technical team** (architecture and operations depth)
2. **Customer audience** (business value and trust confidence)

---

## 1) Internal Demo (20–25 minutes)

### Opening (2 min)

- Problem statement: guest access visibility is fragmented.
- Goal: produce a repeatable, auditable effective-permissions view.

### Architecture Walkthrough (6 min)

- Use: `docs/guest-permissions-architecture.md`
- Emphasize separation of infrastructure, privilege grants, and runtime collection.

### Deployment Walkthrough (6 min)

- Use: `docs/guest-permissions-deploy-to-azure.md`
- Show validation script, deploy script, and smoke test script.

### Security & Governance (5 min)

- Use: `docs/guest-permissions-security-governance.md`
- Highlight least-privilege model and audit gates.

### Close (2–4 min)

- Use readiness checklist and call out production steps.

---

## 2) Customer Demo (15–20 minutes)

### Opening value framing (2 min)

- "We can show who your guest users are, what they can access, and why that access exists."

### Show deployment confidence (4 min)

- Deploy button + runbook + smoke test flow.
- Explain why this is enterprise-safe (separation of duties, validation gates).

### Show operational value (6 min)

- Explain runtime -> telemetry -> dashboard pipeline.
- Show how teams identify risky guest access quickly.

### Show governance readiness (4 min)

- Security model, controls, and checklist.

### Customer next step (2–4 min)

- Agree on pilot environment and success criteria.

---

## 3) Demo Prep Checklist

- [ ] Template validation script passes
- [ ] Deployment script completes
- [ ] Smoke test script passes
- [ ] Dashboard has recent data
- [ ] Architecture diagram reviewed
- [ ] Security model and permission matrix reviewed

---

## 4) Suggested Talk Track Lines

- "This is infrastructure-first to reduce risk and increase repeatability."
- "Identity grants are intentionally separate so they can be reviewed and approved."
- "Evidence is retained and queryable, not just displayed once."
- "The same package works for internal teams and customer handoff."
