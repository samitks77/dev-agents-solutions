# Demo Playbook

A 30-minute technical demo. Works for a security architect, an identity team, or a SOC lead.

## Before you walk in

| Item | Status |
|---|---|
| Detection layer deployed, smoke test passing | Required |
| Entra diagnostics configured **at least 24 hours ago** | Required — 30 minutes is not enough for the workbook to look convincing |
| CA policy created in report-only | Required |
| `invoke-poc-risk-simulation.ps1` run **30 minutes before** the meeting | Required — the logs need time to land |
| POC guide open in a browser tab | Recommended |
| Workbook open in a second tab | Recommended |

> The single most common demo failure is running the simulation live and finding empty sign-in logs.
> Entra takes 15–30 minutes to surface them. Run it before the call and use the live run only as a
> narrative device.

---

## The opening (2 minutes)

Do not start with architecture. Start with the asymmetry.

> "Your user accounts have MFA, risk-based Conditional Access, and a human who notices when
> something is wrong.
>
> Your service principals have a static secret, often a two-year expiry, frequently no owner, and
> usually more permissions than they need. They authenticate at machine speed, non-interactively, so
> anomalous behaviour hides inside normal volume.
>
> Which one would you attack?"

Then the reframe:

> "Workload Identity Protection brings the same adaptive controls to the identities nobody is
> watching. I want to show you the attack, the detection, and the block — and then what it costs to
> run."

---

## Act 1 — The attack nobody sees (6 minutes)

**Show:** Entra portal → App registrations → a POC app → Certificates & secrets → two credentials.

**Say:**

> "An attacker who reaches an app registration adds their own client secret. It takes one click.
> They now hold a key to this application that is completely independent of the original.
>
> Rotating the legitimate secret does not evict them. There is no alert on this by default. This is
> MITRE T1098.001, and it is the quietest persistence technique available against a cloud identity."

**Show:** the audit log entry, then detection D1 returning that exact event.

**Say:**

> "The audit log recorded it — actor, timestamp, before-and-after credential count. It was always
> there. The gap is that nothing was watching. That is a 15-line KQL query."

**Why this lands:** it is concrete, they can verify it in their own tenant in two minutes, and most
teams have genuinely never looked at this.

---

## Act 2 — Behaviour, not entitlement (6 minutes)

**Show:** workbook → *Resource reach per workload identity*.

**Say:**

> "A legitimate service principal is provisioned for a job. It touches one or two resources, forever.
>
> An attacker with a stolen credential does not know what it can reach — so they enumerate. Graph,
> ARM, Key Vault, Storage, SQL, Power BI, Fabric. Seven resources in ten seconds."

**Show:** detection D3 with the burst identity.

**Say:**

> "Nothing here required an agent or a sensor. This is token issuance telemetry that Entra already
> produces. Which also means it is invisible to the attacker — there is nothing on the host for them
> to detect or disable."

**Then D4:**

> "Same idea, different shape. This identity was provisioned to read SQL. Today it asked for a Fabric
> token for the first time ever. Nothing is technically wrong — the permission may even be granted —
> but the pivot itself is the signal."

**The line to land:**

> "Entitlement reviews tell you what an identity *could* do. This tells you what it *just did*."

---

## Act 3 — From signal to enforcement (6 minutes)

**Show:** Identity Protection → Risky workload identities → an identity at High risk.

**Say:**

> "The SOC investigated and confirmed compromise. One API call. That is the same call your analysts
> would make after a Sentinel alert or a threat intel hit."

**Show:** the Conditional Access policy, in report-only.

**Say:**

> "The policy evaluates service principal risk. Right now it is in report-only — it logs the decision
> and blocks nothing. That is deliberate, and I will come back to why."

**Show:** enforce it, then run a token request that fails.

```
AADSTS53003: Access has been blocked by Conditional Access policies.
The access policy does not allow token issuance.
```

**Say:**

> "The block happens at the token issuance layer. This identity now gets nothing — not Graph, not
> ARM, not Key Vault, not Fabric. No agent, no application change, and it took under two minutes to
> take effect tenant-wide."

**Revert to report-only in front of them.** It demonstrates that rollback is instant and builds
trust that this is safe to try.

---

## Act 4 — The part that earns credibility (6 minutes)

This is where most demos stop. Do not stop here.

**Say:**

> "Everything so far was a demo. Here is what happens when you actually deploy it."

**Show:** detection D6, report-only enforcement readiness.

**Say:**

> "Blocking a workload identity is an outage. There is no user to call the help desk — it surfaces as
> a batch job that silently stopped, or an API returning 401s to your customer.
>
> This query answers the only question that matters before you enforce: *if I turn this on right now,
> what breaks?* `WouldHaveBlocked` is your blast radius. You run it after a week in report-only. If
> it is zero, enforcing is safe. If it is not, every identity on that list needs an owner before you
> go any further."

**Then be honest about the constraints:**

| Reality | Say it before they ask |
|---|---|
| Workload Identities Premium is a separate SKU | "It is not in P2. Budget for it, and check it first — it is the number one reason these POCs stall." |
| ML detections need weeks of baseline | "In a fresh tenant there is no baseline, so the automatic detections cannot fire. That is why the POC uses admin confirmation to simulate the end state. In production the ML fires on its own from about week three." |
| D4 is noisy for 14 days | "Expect noise while the baseline fills. Do not tune it down in week one." |
| Sign-in log volume costs money | "`ServicePrincipalSignInLogs` is usually the biggest category in a large tenant. Set a daily cap and review after the first day." |

**Why this act matters more than the other three:** a technical audience assumes any demo is
rehearsed. Volunteering the constraints before they find them is what converts a demo into a
deployment conversation.

---

## Closing (4 minutes)

**Show:** the repository.

**Say:**

> "This is not slideware. The ARM template, the five detections, the Conditional Access policy, the
> simulation script, and the runbooks are all here. A Deploy to Azure button, then two scripts.
>
> The POC guide walks the whole thing manually if you want to understand each step, or the simulation
> script does it in one command."

**The ask:**

> "Run it in a test tenant. Point it at your own service principals in report-only. In a week, D6
> will tell you what enforcing would actually break — and that number is the real start of the
> conversation."

---

## Questions you will get

| Question | Answer |
|---|---|
| "Does this need an agent?" | No. It is Entra token issuance telemetry — nothing on any host. |
| "Will it break my applications?" | Not in report-only, which is the default. D6 quantifies the impact before you enforce. |
| "We already have Sentinel." | Same KQL. Drop the detections in as analytics rules; skip the workspace. |
| "How is this different from PIM?" | PIM governs *entitlement* — what an identity may do. This governs *behaviour* — what it just did. Complementary. |
| "What about managed identities?" | Covered by the same detections. Enable `ManagedIdentitySignInLogs` in diagnostics. |
| "What if the attacker has the secret already?" | That is the point. This detects the behaviour after the credential is stolen, which is the only window you get. |
| "Cost?" | Log Analytics ingestion, dominated by sign-in logs. Set `dailyQuotaGb`, review after a day, then decide. |
| "Can we auto-block?" | Technically yes; deliberately not built. It would require an identity with tenant-wide DoS capability. [Security doc](workload-identity-security-governance.md) explains the reasoning. |

---

## Post-demo

1. Send the repository link and the POC guide.
2. Offer a working session to deploy into their test tenant — it is genuinely under an hour.
3. Agree a date to review their D6 output. That review is where the deal is.
4. Run `remove-poc-resources.ps1` in your own demo tenant.
