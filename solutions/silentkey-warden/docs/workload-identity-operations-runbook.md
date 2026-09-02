# Operations Runbook

Day-2 operations for the deployed detection layer.

---

## Daily

| Check | Where | Looking for |
|---|---|---|
| Open alerts | Azure Monitor → Alerts, filter by resource group | Anything unacknowledged from D1, D2, D3, D5 |
| Risk posture | Workbook → *Posture at a glance* | New High-risk identities since yesterday |
| Enforced blocks | D5 | A legitimate identity caught by the risk policy |

D4 is severity 3 by design. Review it weekly in batch, not daily.

---

## Alert triage

Every `.kql` file in [`../detections/`](../detections/) carries its own triage guidance in the
header comment. This is the cross-cutting decision procedure.

### D1 — Credential added to an application

**Question:** was this an approved rotation, or someone else's key?

1. Identify `Initiator`. Recognised app owner or automation identity?
2. Is there a change request or pipeline run at that timestamp?
3. Check `InitiatorIp` against expected admin ranges.
4. Correlate: does the same `TargetAppId` appear in D3 or D4 shortly afterwards? A credential
   addition followed by a resource burst is the classic compromise sequence.

**If unauthorised:** confirm compromised → remove the rogue credential → rotate the legitimate one →
dismiss the risk. **In that order.** Removing the credential first tips off the attacker while they
still hold a valid token.

### D2 — Risky workload identity detected

**Question:** who or what decided this, and how confident are they?

Read `RiskEventType` first:

| `RiskEventType` | Source | Confidence | Action |
|---|---|---|---|
| `adminConfirmedServicePrincipalCompromised` | A human already investigated | Definitive | Find their ticket. Do not re-investigate from scratch. |
| `leakedCredentials` | Microsoft Threat Intelligence | Very high | Rotate immediately. The secret is public. |
| `suspiciousSignIns` | Entra ML | Medium | Corroborate with D3, D4, and source IP reputation |
| `anomalousServicePrincipalActivity` | Entra ML | Medium | Corroborate. Check whether a legitimate change explains it. |
| `maliciousApplication` | Microsoft Threat Intelligence | High | Escalate. The app matches a known campaign. |

**If the CA policy is enforced, this identity is already blocked.** Your job is to decide whether to
dismiss the risk (restoring access) or leave it contained.

### D3 — Multi-resource burst sign-in

**Question:** does the resource list look like a job, or a shopping list?

1. Do the resources form a coherent workflow (Storage + SQL for an ETL job), or an enumeration
   sweep (Graph + ARM + Key Vault + Storage + SQL + Power BI + Fabric)?
2. `BurstDurationSeconds` — seconds apart is scripted; minutes apart may be a normal batch window.
3. Single source IP or several?
4. Cross-check D1 for a recent credential addition on the same `AppId`.

**Known-good fan-out identities** — CSPM scanners, backup orchestrators, cost tools — should be
added to `KnownFanOutApps` in the query rather than raising `burstResourceThreshold` for everyone.

### D4 — First-time resource access

**Question:** is there a change record for this integration?

1. Does the new resource fit the identity's stated purpose?
2. Is there a ticket or deployment at that timestamp?
3. Is it part of a burst (check D3)? A first-time access inside a burst is materially worse than a
   lone one.

**During the first 14 days after deployment, expect heavy noise.** The baseline is empty. Do not
tune this down before the window fills.

### D5 — Blocked by Conditional Access

**Question:** containment working, or production broken?

1. Look up the `AppId` in D2. Is there a genuine risk detection behind the block?
2. **Yes** → containment is working. Continue the investigation, leave it blocked.
3. **No**, or the risk was an admin confirmation made in error → dismiss the risk in Identity
   Protection to restore access. No secret rotation is needed if the identity was never compromised.

---

## Incident response — confirmed compromised workload identity

**Containment (minutes)**

1. Confirm the identity compromised:

   ```bash
   az rest --method post \
     --url "https://graph.microsoft.com/v1.0/identityProtection/riskyServicePrincipals/confirmCompromised" \
     --body '{"servicePrincipalIds":["<sp-object-id>"]}' \
     --headers "Content-Type=application/json"
   ```

2. If the CA policy is in report-only, enforce it, or block this identity specifically.
3. Verify containment: D5 should show `AADSTS53003` for that identity within 1–2 minutes.

**Investigation (hours)**

4. Full resource reach:

   ```kusto
   AADServicePrincipalSignInLogs
   | where TimeGenerated > ago(30d)
   | where ServicePrincipalId == "<sp-object-id>"
   | summarize SignIns = count(), First = min(TimeGenerated), Last = max(TimeGenerated),
               IPs = make_set(IPAddress, 50) by ResourceDisplayName
   | order by Last desc
   ```

5. Full configuration history:

   ```kusto
   AuditLogs
   | where TimeGenerated > ago(90d)
   | where TargetResources has "<app-id>"
   | project TimeGenerated, OperationName, InitiatedBy, Result, TargetResources
   | order by TimeGenerated desc
   ```

6. Determine the earliest anomalous event. That is the start of the compromise window, and
   everything the identity touched after it is in scope.

**Eradication**

7. Remove **all** credentials on the app registration, not just the suspicious one.
8. Issue a new credential only after the investigation closes.
9. Review and reduce the identity's role assignments — a compromise is the best opportunity you will
   get to fix over-permissioning.
10. Prefer workload identity federation over a static secret for the replacement.

**Recovery**

11. Dismiss the risk to restore access.
12. Verify the workload resumes.
13. Confirm D5 stops firing for that identity.

---

## Maintenance

### Weekly

- Review D4 output in batch.
- While the CA policy is in report-only, run D6 and track whether `WouldHaveBlocked` is trending
  toward zero.

### Monthly

- **Ingestion cost.** `ServicePrincipalSignInLogs` dominates. If volume is unexpected:

  ```kusto
  Usage
  | where TimeGenerated > ago(30d)
  | where IsBillable == true
  | summarize BillableGB = sum(Quantity) / 1000 by DataType
  | order by BillableGB desc
  ```

- **D3 tuning.** If the same benign identities keep appearing, add their `AppId` to
  `KnownFanOutApps` rather than raising the threshold globally.
- **Alert volume per rule.** A rule that never fires and a rule that always fires are both broken.

### Quarterly

- Re-run the [enterprise readiness checklist](workload-identity-enterprise-readiness-checklist.md).
- Review who holds `IdentityRiskyServicePrincipal.ReadWrite.All`.
- Confirm retention still meets the compliance requirement.

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| All detections silent | Diagnostic settings missing or removed | Re-run `configure-entra-diagnostics.ps1` |
| Only D2 silent | No Workload Identities Premium licence | Verify licensing; other detections are unaffected |
| Tables exist, no recent rows | Ingestion delay or daily cap hit | Check `Usage`; a hit cap silently drops data |
| Alerts fire, nobody notified | Action group has no receivers | Add a receiver; the smoke test flags this |
| D4 flooding | Baseline still filling | Expected for 14 days after deployment |
| D3 noisy | Legitimate fan-out identities | Add to `KnownFanOutApps` |
| Rule shows "query failed" | Table does not exist yet | Configure diagnostics; `skipQueryValidation` allowed it to deploy early |
| Legitimate identity blocked | Risk detection on a healthy identity | Dismiss the risk. No rotation needed if it was not compromised. |
| Cannot confirm compromised (403) | Missing Graph consent | Consent to `IdentityRiskyServicePrincipal.ReadWrite.All` |
| Duplicate workbooks | Non-deterministic name | The template uses a deterministic `guid()`; delete manual copies |

### Health check — is this thing on?

```kusto
union withsource = SourceTable
    (AuditLogs | where TimeGenerated > ago(24h)),
    (AADServicePrincipalSignInLogs | where TimeGenerated > ago(24h)),
    (AADServicePrincipalRiskEvents | where TimeGenerated > ago(24h))
| summarize Rows = count(), Latest = max(TimeGenerated) by SourceTable
| extend MinutesSinceLastRow = datetime_diff('minute', now(), Latest)
| extend Health = iff(MinutesSinceLastRow > 120, "STALE - investigate", "OK")
```

`AADServicePrincipalRiskEvents` legitimately has no rows if no risk has been detected. The other two
should always be recent in an active tenant.
