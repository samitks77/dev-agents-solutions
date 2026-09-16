# Enterprise PAR Requirement-to-Proof Matrix

This document is the acceptance contract for the verified Playwright authentication solution. It
captures the functional enterprise requirements without publishing customer correspondence,
customer tenant information, or customer names.

## Outcome

Run unattended Playwright browser tests in GitHub Actions against an application protected by
Microsoft Entra user authentication while preserving strong Conditional Access controls,
deterministic network egress, private certificate retrieval, exact evidence correlation, and
verified cleanup.

The solution is not accepted because a browser reached a page. It is accepted only when the
independent GitHub, Azure, Playwright, Entra sign-in, policy-restoration, and cleanup evidence all
agree on the exact run.

## Complete requirement coverage

| Enterprise requirement | Implemented response | Required proof | Acceptance rule |
|---|---|---|---|
| Run Playwright from GitHub Actions against a real Entra-protected application | A GitHub workflow targets a unique one-job self-hosted runner created in Azure Container Instances. Playwright presents a PFX only to the exact Entra certificate-authentication origin. | GitHub workflow, job and Playwright step; bounded identity receipt | Exact repository, workflow, run, branch, commit, runner label, application origin, user, tenant and object ID must match. |
| Authenticate unattended without a password or interactive MFA prompt | Microsoft Entra CBA authenticates a dedicated test user with an X.509 certificate. The certificate is retrieved at runtime rather than committed to GitHub. | Successful Playwright sign-in and correlated Entra sign-in | Authentication method must be certificate-based authentication and the exact identity claims must be rendered by the relying application. |
| Avoid a broad MFA exception | The positive certificate is classified as MFA through its policy OID and satisfies the built-in phishing-resistant authentication strength. No user or tenant-wide MFA bypass is the production mechanism. | Positive Conditional Access receipt | Under one exact correlation, a terminal record must have error code `0`, the lab policy must record `success`, and CBA must show `multiFactorAuthentication`, a successful X.509 step and the modern PKI store. Companion Entra records are accepted only inside that correlation and neither `failure` nor `reportOnlyFailure` may exist for the lab policy. |
| Prove that Conditional Access is actually enforcing certificate strength | A second certificate for the same identity intentionally omits the MFA policy OID and is classified as SFA. | Negative Conditional Access receipt | Exact lab policy must be `failure`, error code `500187`, certificate level `singleFactorAuthentication`, failed X.509 step, modern PKI store. |
| Isolate causality from unrelated tenant-wide policies | During the bounded negative proof, only the lab application is temporarily excluded from an explicit allowlist of interfering Microsoft-managed policies. Every original exclusion set and invariant hash is journaled and restored. This isolation is a test-control transaction, not the production authentication design. | Correlated sign-in plus schema-v3 isolation journal bound to the cloud proof set | Exact lab policy must fail; every isolated policy must be `notApplied`; no unexpected policy may fail; all baseline exclusions must be restored. |
| Provide a fixed runner egress IP for named-location or inspection controls | The ACI-delegated subnet uses Azure NAT Gateway with a static public IP. | Live ARM topology and runner-network receipt | Runner subnet, NAT resource and observed outbound IP must match exactly. NAT provides outbound connectivity only. |
| Keep certificate retrieval on a private Azure path | Key Vault public network access is disabled. The runner resolves the standard vault hostname through `privatelink.vaultcore.azure.net` to the exact Private Endpoint IP. | Live ARM/DNS topology and in-run Key Vault receipt | Vault default action must be `Deny`; one approved `vault` Private Endpoint, NIC, DNS record and VNet link must agree; secret reads must succeed. |
| Avoid long-lived Azure credentials in GitHub | GitHub issues an OIDC token whose issuer, audience, immutable repository identity, environment, run and commit are validated before Azure token exchange. Deployment identifiers use encrypted environment secrets for automatic log masking; the certificate and passphrase remain only in Key Vault. | GitHub OIDC commitment, encrypted-secret name read-back and Azure federated-credential read-back | The exact default GitHub subject commitment must match. The workflow receives `id-token: write`; no GitHub secret stores an Azure client secret, certificate or certificate passphrase. |
| Prevent certificate disclosure to an unintended origin | Playwright configures the client certificate only for the exact Entra certificate-authentication origin and runs a wrong-origin negative control. | Wrong-origin Playwright receipt | The unapproved origin must not receive a client certificate. |
| Make repeated and resumed browser behavior testable | The suite includes five independent fresh-session runs and an authenticated-session reuse test. | Reliability and session receipts | All fresh runs must pass; session reuse must reach the application without a new certificate-authentication request. |
| Produce bounded, reviewable evidence | Runtime output is reduced to allowlisted commitment-only JSON in one size-bounded transient GitHub artifact. Public job-log receipt fallback is disabled. Both receipts replace raw identity, network, OIDC and runner identifiers with SHA-256 commitments or bounded assertions. | Receipt schema, file size, SHA-256 and cross-record checks | Missing, oversized, stale, ambiguous, cross-run or identity-mismatched evidence fails closed. No private key, passphrase, token, raw identity, network topology, OIDC subject or raw sign-in payload is published. |
| Prevent public workflow-output disclosure | The launcher re-downloads the completed GitHub job log and checks exact, URL-encoded and Base64-encoded variants of all ignored local deployment values. The public workflow run name contains no verification identifier. | Live log replay, protected-value count, variant count and immutable log SHA-256 | Any protected value in the log fails the proof. The transient receipt artifact must be deleted after verified local download, and live GitHub API replay must return zero matching artifacts. A run whose log cannot be verified is deleted with its logs. |
| Remove transient access and compute | The runner is registered `--ephemeral`; runtime credentials are shredded; the transient artifact is deleted; the ACI container is deleted; runner deregistration is queried; the lab CA policy returns to report-only. | Live GitHub/Azure queries and policy journals | Zero matching artifacts, ACI containers and repository runners; Conditional Access restoration must be exact. |
| Explain the supported production choices | The documentation distinguishes the validated ACI runner from GitHub-hosted larger runners with Azure private networking. | Architecture decision and official references | Do not claim that the ACI design is an official combined reference architecture or that every GitHub plan supports hosted-runner VNet injection. |

## Private Endpoint versus Private Link Service

Private Link Service is not a missing component.

- **Private Endpoint is used:** the runner is a client of Key Vault, so a Key Vault Private Endpoint
  places that service endpoint inside the Azure VNet.
- **Private Link Service is not used:** it publishes a provider-owned inbound service behind a
  Standard Load Balancer. The runner does not expose an inbound service; it polls GitHub over
  outbound HTTPS.
- **Static egress is separate:** NAT Gateway supplies the predictable outbound address used for
  named-location and inspection controls.

Adding Private Link Service to this design would create an unused inbound surface and would not
make the Key Vault data path more private.

## Why the proof has two linked gates

The verified outcome combines two independently correlated gates:

1. **Cloud execution gate:** GitHub Actions → ephemeral Azure runner → GitHub OIDC → private Key
   Vault retrieval → Playwright → exact Entra identity.
2. **Policy enforcement gate:** MFA certificate succeeds → SFA certificate fails the exact
   phishing-resistant policy → interfering policies are proven `notApplied` → all policies are
   restored.

The policy-isolation transaction is intentionally operator-controlled and is not placed inside an
ordinary CI job. It requires Graph privileges, an exclusive Conditional Access maintenance window,
an explicit allowlist of policies, and enough token lifetime to restore safely. Combining those
privileges with routine repository code would weaken separation of duties.

## Production runner choice

| Option | Use when | Network result | Boundary |
|---|---|---|---|
| GitHub-hosted larger runner with Azure private networking | The organization has the required GitHub plan, billing and enterprise configuration and wants GitHub-managed compute | GitHub injects the runner NIC into a delegated Azure VNet; VNet routing and controls apply | Confirm entitlement and supported runner images with GitHub. |
| Autoscaled ephemeral self-hosted runner in Azure | The organization needs direct control of compute, image, subnet and static egress or cannot use the hosted VNet feature | Azure owns the runner compute, subnet, NAT and private service paths | Treat workflow authors as highly privileged; destroy the execution environment after one job and export runner diagnostics for production. |

This POC validates the second option with an ephemeral ACI container. It does not claim that
Microsoft or GitHub publishes this exact combined ACI runner architecture.

## Authoritative implementation references

- [Playwright client certificates](https://playwright.dev/docs/api/class-browser#browser-new-context-option-client-certificates):
  exact-origin PFX/PKCS#12 client-certificate configuration.
- [Microsoft Entra CBA overview](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication):
  cloud-native X.509 user authentication.
- [Configure Entra CBA binding rules](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-certificate-based-authentication#step-3-configure-an-authentication-binding-policy):
  SFA/MFA classification and policy-OID rules.
- [Conditional Access authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths):
  phishing-resistant MFA and CBA strength behavior.
- [GitHub OIDC with Azure](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure):
  short-lived federation and `id-token: write`.
- [GitHub ephemeral self-hosted runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#ephemeral-runners-for-autoscaling):
  one-job runner registration and deregistration.
- [GitHub self-hosted runner hardening](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners):
  trust and compromise boundaries.
- [GitHub-hosted runner Azure private networking](https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/configuring-private-networking-for-hosted-compute-products/about-azure-private-networking-for-github-hosted-runners-in-your-enterprise):
  the enterprise larger-runner VNet model and its outbound-only behavior.
- [GitHub larger runners](https://docs.github.com/en/actions/concepts/runners/larger-runners):
  plan, billing and runner capability boundaries.
- [ACI in a VNet](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-vnet):
  delegated-subnet requirements.
- [ACI with NAT Gateway](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-nat-gateway):
  supported VNet egress and static outbound addressing.
- [Azure NAT Gateway](https://learn.microsoft.com/en-us/azure/nat-gateway/nat-overview):
  outbound SNAT and unsolicited inbound protection.
- [Key Vault Private Link](https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service):
  private endpoints and disabled public access.
- [Private Endpoint DNS](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns):
  `privatelink.vaultcore.azure.net` resolution.
- [Azure Private Link Service](https://learn.microsoft.com/en-us/azure/private-link/private-link-service-overview):
  provider-side publication of an inbound service.

## Explicit nonclaims

- Playwright and Microsoft document their component capabilities separately; neither publishes a
  product support statement for this exact Playwright-to-Entra-CBA browser integration. The
  integration is therefore proven experimentally by this repository.
- No named external customer implementation is claimed.
- No prior run from another repository satisfies the target-repository gate.
- Runtime evidence is not source code. It remains ignored locally unless a separately sanitized,
  environment-safe proof summary is deliberately published.
