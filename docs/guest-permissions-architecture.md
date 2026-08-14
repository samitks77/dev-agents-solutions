# Guest Permissions Solution — Architecture

## 1) Architecture Goals

1. Provide deterministic visibility into guest user access.
2. Separate bootstrap infrastructure from privileged identity grants.
3. Keep runtime collection observable, auditable, and repeatable.
4. Support both manual and automated operation modes.

---

## 2) Component Diagram

```mermaid
flowchart TD
  subgraph ControlPlane[Control Plane]
    U[Operator / IAM Analyst]
    A[M365 Agent (Optional)]
    CP[Run Trigger + Status APIs]
  end

  subgraph RuntimePlane[Runtime Plane]
    J[Container Apps Job Runtime]
    MI[User-Assigned Managed Identity]
  end

  subgraph DataSources[Security Data Sources]
    G[Microsoft Graph\nGuests, Groups, Roles, PIM]
    R[Azure ARM\nRBAC + Deny Assignments]
    D[Service APIs\nData-plane ACL Signals]
  end

  subgraph EvidencePlane[Evidence + Observability]
    S[Azure Files\nSnapshots]
    L[Log Analytics\nPipeline Telemetry]
    F[Grafana\nDashboards]
  end

  U --> CP
  A --> CP
  CP --> J
  J --> MI
  MI --> G
  MI --> R
  MI --> D
  J --> S
  J --> L
  L --> F
  U --> F
```

---

## 3) Component Responsibilities (What + Why)

| Component | What it does | Why it exists |
|---|---|---|
| Managed Identity | Authenticates runtime without embedded secrets | Reduces secret sprawl and supports enterprise identity governance |
| Container Apps Job | Runs collection and resolution stages | Supports scheduled and on-demand execution with isolation |
| Graph + ARM + Service APIs | Source-of-truth control/data-plane permissions | Ensures complete guest access context across identity and resource layers |
| Azure Files | Stores run snapshots and artifacts | Preserves evidence for audit, comparison, and rollback analysis |
| Log Analytics | Stores run telemetry and execution signals | Enables operational monitoring and KPI tracking |
| Managed Grafana | Provides dashboards for analysts and leadership | Converts raw telemetry into actionable, visual insight |
| M365 Agent (optional) | Human-friendly trigger + status interface | Speeds analyst workflows and improves adoption |

---

## 4) Trust Boundaries

1. **Operator boundary**: Human-initiated actions should be RBAC-gated and auditable.
2. **Runtime boundary**: Collection runtime should use least-privilege managed identity.
3. **Data boundary**: Snapshot storage and logs should be restricted by environment RBAC and retention policies.
4. **Presentation boundary**: Dashboard read access should be role-based and scoped.

---

## 5) Failure Domains and Recovery

| Failure domain | Typical symptom | Recovery action |
|---|---|---|
| Identity grants missing | API authorization errors during collection | Re-apply Graph/Azure role grants, re-run |
| Runtime config drift | Job starts but no useful output | Validate env vars/command sequence and image version |
| Telemetry ingestion issue | Job runs but dashboard empty | Validate Log Analytics wiring and query scope |
| Dashboard misconfiguration | Data exists but not visible | Reconfigure datasource/import dashboard JSON |

---

## 6) Enterprise Design Choices

- **Separation of infra and privilege**: safer change control and approvals.
- **Idempotent bootstrap**: easier re-deploys and environment parity.
- **Scripted validation and smoke tests**: faster handoff and confidence.
- **Doc-first runbooks**: predictable operations for internal and customer teams.
