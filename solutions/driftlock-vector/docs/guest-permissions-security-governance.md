# Guest Permissions Solution — Security and Governance

## 1) Security Objectives

1. Enforce least privilege for runtime and operators.
2. Keep every high-impact action auditable.
3. Separate deployment, identity grants, and runtime execution controls.
4. Protect permission evidence data through scoped access and retention.

---

## 2) Identity Model

### Runtime identity (managed identity)

**What it does**

- Authenticates the collector runtime to Graph, ARM, and service APIs.

**Why it matters**

- Avoids long-lived client secrets in code/config and aligns with enterprise identity patterns.

### Operator identity (human)

**What it does**

- Deploys infrastructure, approves identity grants, and monitors operation.

**Why it matters**

- Keeps operational ownership explicit and auditable.

### Optional agent identity

**What it does**

- Runs control-plane actions for run trigger/status in M365 experiences.

**Why it matters**

- Enables controlled delegation without giving broad infrastructure rights to every user.

---

## 3) Permission Model (Baseline)

| Principal | Scope | Minimum expected access |
|---|---|---|
| Deployment operator | Resource group/subscription | Resource creation + RBAC assignment as approved by policy |
| Runtime managed identity | Graph + Azure APIs | Read-level permissions required for guest/group/role/PIM and RBAC discovery |
| Grafana viewer/operator | Grafana + Log Analytics | Reader access for dashboards and telemetry queries |

> Final permissions should be aligned with your internal IAM and compliance controls.

---

## 4) Governance Guardrails

1. Use separate change approvals for:
   - Infrastructure changes
   - Identity/permission grant changes
2. Track all production deployments with deployment name, operator, and timestamp.
3. Use environment-specific parameter files (dev/test/prod).
4. Keep retention and access review policy documented and reviewed quarterly.

---

## 5) Data Handling

| Data class | Location | Control recommendation |
|---|---|---|
| Snapshot artifacts | Azure Files | Restrict write/read to runtime + authorized operators |
| Pipeline telemetry | Log Analytics | Restrict workspace query rights; apply retention policy |
| Dashboard metadata | Managed Grafana | Role-based access with named groups |

---

## 6) Audit and Evidence

Capture and retain:

1. ARM deployment history
2. RBAC assignment changes
3. Runtime execution history
4. Dashboard access and changes (where available)

These records are critical for internal audit and customer assurance reviews.

---

## 7) Production Readiness Security Gates

Before go-live:

- [ ] Runtime identity permissions are least-privilege and documented
- [ ] Operator access is group-based (not per-user exceptions)
- [ ] Data retention and purge policy is approved
- [ ] Incident response owner is assigned
- [ ] Break-glass path is defined and tested
