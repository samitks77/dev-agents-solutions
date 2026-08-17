# Guest Permissions Solution — Enterprise Readiness Checklist

Use this checklist before internal showcase and customer-facing demo.

## 1) Platform Readiness

- [ ] ARM template and parameter file validated
- [ ] Deployment can be repeated idempotently
- [ ] Resource naming conventions documented
- [ ] Environment separation plan exists (dev/test/prod)

## 2) Security Readiness

- [ ] Runtime managed identity is configured
- [ ] Required Graph/Azure permissions documented and approved
- [ ] Operator access is role-based (group-driven preferred)
- [ ] Dashboard/workspace access is least privilege

## 3) Operations Readiness

- [ ] Smoke test script passes in target environment
- [ ] Run failure escalation owner assigned
- [ ] Monitoring KPIs defined (success rate, duration, coverage)
- [ ] Recovery playbook documented for common failures

## 4) Governance Readiness

- [ ] Deployment and permission changes are auditable
- [ ] Retention policy for snapshots/logs is defined
- [ ] Quarterly access review owner assigned
- [ ] Customer handoff artifacts are complete

## 5) Demo Readiness

- [ ] Internal demo flow rehearsed
- [ ] Customer demo flow rehearsed
- [ ] Architecture and runbook links verified
- [ ] Known limitations and next steps prepared

## 6) Final Sign-Off

- [ ] Technical lead sign-off
- [ ] Security lead sign-off
- [ ] Operations owner sign-off
- [ ] Customer-facing presenter sign-off
