# Azure Deploy Template Guide

## Files

- `entra-cba-playwright-infrastructure.json` — ARM template compiled from the portal-safe
  [`../../infra/portal.bicep`](../../infra/portal.bicep) wrapper with pinned Bicep v0.41.2. The
  wrapper invokes [`../../infra/main.bicep`](../../infra/main.bicep) and deliberately removes
  arbitrary CIDR inputs from the portal experience.
- `entra-cba-playwright-infrastructure.parameters.json` — a parameters-file skeleton for CLI or
  PowerShell deployment using the safe default network profile.

## What gets deployed

This template deploys **Azure resource-plane infrastructure only**. Creating its two user-assigned
managed identities causes Azure to create two backing Microsoft Entra service principals; the
template requires an explicit acknowledgement of that directory side effect. It does not
authenticate an operator to Microsoft Graph or GitHub, create users or groups, configure CBA or
Conditional Access, or enable a tenant policy. Those later steps are performed by
[`../../scripts/Bootstrap-PostDeploy.ps1`](../../scripts/Bootstrap-PostDeploy.ps1).

| Resource | Count | Purpose |
|---|---|---|
| `Microsoft.OperationalInsights/workspaces` | 1 | Key Vault audit/diagnostic destination |
| `Microsoft.ManagedIdentity/userAssignedIdentities` | 2 | GitHub OIDC workload identity + Key Vault secret-publisher identity |
| `Microsoft.Network/publicIPAddresses` + `natGateways` | 1 each | Deterministic static outbound IP for the ephemeral runner subnet |
| `Microsoft.Network/virtualNetworks` (+ 2 subnets) | 1 | ACI-delegated runner subnet and a private-endpoint subnet |
| `Microsoft.KeyVault/vaults` | 1 | Private, RBAC-only vault for the disposable PFX + passphrase |
| `Microsoft.Network/privateDnsZones` (+ link) + `privateEndpoints` | 1 each | Private-only Key Vault resolution path |
| `Microsoft.Web/staticSites` | 1 | Relying-party test application host |
| `Microsoft.Authorization/roleAssignments` | 1 | Key Vault Secrets User for the GitHub workload identity |

## Deploy options

### Option 1 — Deploy to Azure button (infrastructure only)

Use the button in the solution's [`README.md`](../../README.md). The button deploys only the
resources above; it never authenticates to Microsoft Graph, GitHub, or Conditional Access. Confirm
the disclosed managed-identity service-principal creation, select one of the three predefined
RFC1918 profiles, and choose a profile that does not overlap with any network you may later connect
to the isolated lab.

### Option 2 — Wrapper script (recommended for repeat deployments)

```powershell
./scripts/Deploy-Infrastructure.ps1 `
  -Subscription <subscription-id> `
  -ExpectedTenantId <tenant-id> `
  -ResourceGroup <resource-group-name> `
  -Location eastus2 `
  -VirtualNetworkAddressPrefix <non-overlapping-rfc1918-vnet-prefix> `
  -RunnerSubnetAddressPrefix <non-overlapping-rfc1918-runner-subnet-prefix> `
  -PrivateEndpointSubnetAddressPrefix <non-overlapping-rfc1918-private-endpoint-subnet-prefix> `
  -ConfirmManagedIdentityServicePrincipals
```

This wrapper additionally captures deployment outputs into `.lab-state\infrastructure.json` for the
rest of the runbook. The Deploy to Azure button bypasses this capture step by design (the portal
has no local disk to write to), which is why
[`Bootstrap-PostDeploy.ps1`](../../scripts/Bootstrap-PostDeploy.ps1) independently rediscovers and
verifies the same outputs after a button deployment.

### Option 3 — Azure CLI

The checked-in parameters file selects the safe `10-range` profile. Change only `networkProfile` to
`172-range` or `192-range` if necessary:

```bash
az deployment group create \
  --resource-group <resource-group-name> \
  --template-file templates/azuredeploy/entra-cba-playwright-infrastructure.json \
  --parameters @templates/azuredeploy/entra-cba-playwright-infrastructure.parameters.json \
  confirmManagedIdentityServicePrincipals=true
```

## Parameter reference

| Parameter | What it controls | Why it exists |
|---|---|---|
| `location` | Deployment region | Must support ACI, NAT Gateway, Key Vault, and Static Web Apps |
| `tags` | Tags on every resource | Cost attribution and lab inventory |
| `networkProfile` | One of `10-range`, `172-range`, or `192-range` | Selects a predefined VNet plus non-overlapping ACI and Private Endpoint subnets; arbitrary portal CIDRs are not accepted |
| `confirmManagedIdentityServicePrincipals` | Must be `true` | Explicitly acknowledges that Azure creates one backing Entra service principal for each user-assigned managed identity |

For custom CIDRs, use `Deploy-Infrastructure.ps1`. That path validates RFC1918 containment,
non-overlap, prefix size and reserved-address capacity before deployment.

## Outputs reference

| Output | Consumed by |
|---|---|
| `appUrl`, `crlUrl` | `Deploy-TestApp.ps1`, `New-LabPki.ps1` |
| `runnerVaultName`, `keyVaultPrivateEndpointName` | `Bootstrap-PostDeploy.ps1`, `Publish-LabAssets.ps1`, `Show-E2eProof.ps1` |
| `workloadClientId`, `workloadIdentityName`, `workloadPrincipalId`, `workloadResourceId` | `Configure-GitHubOidc.ps1` |
| `publisherClientId`, `publisherIdentityName`, `publisherPrincipalId`, `publisherResourceId` | `Publish-LabAssets.ps1` |
| `runnerSubnetId`, `runnerOutboundIpAddress`, `virtualNetworkName` | `Runner-Network.ps1`, `Start-EphemeralGitHubRunner.ps1` |
| `logAnalyticsWorkspaceName`, `staticWebAppName` | `Show-E2eProof.ps1` |

The checked-in template contains expressions, never populated deployment outputs.
`Bootstrap-PostDeploy.ps1` independently re-verifies every output against live Azure state before
trusting it, because a portal deployment cannot write authenticated state to the operator's disk.

## Regenerating this file

```powershell
az bicep install --version v0.41.2
az bicep build --file ../../infra/portal.bicep --outfile entra-cba-playwright-infrastructure.json
```

Run this whenever `infra/portal.bicep` or `infra/main.bicep` changes and commit the regenerated JSON
in the same change. `entra-cba-solution-quality.yml` installs the same pinned compiler, recompiles
`portal.bicep` on every push/PR, and fails on byte-for-byte drift.

## Validation guidance

Commands below assume you are in `solutions/entra-cba-playwright/`:

1. Compile check (no Azure session needed):

   ```powershell
   az bicep install --version v0.41.2
   az bicep build --file infra/portal.bicep --outfile "$env:TEMP/entra-cba-portal.json"
   ```

2. Public-template safety check (no Azure session needed):

   ```powershell
   ./scripts/Test-PublicTemplate.ps1
   ```

3. Static/public-proof tier of the unified verifier (no tenant access):

   ```powershell
   ./scripts/Invoke-EntraCbaVerification.ps1 -Tier PublicProof
   ```

## Known behaviours that are intentional

- **The button requires acknowledgement of two backing Entra service principals.** No other Entra,
  GitHub, CBA, or Conditional Access configuration occurs until the separately authenticated
  bootstrap consent gate.
- **Deployment succeeds but nothing is usable yet.** Expected until an authorized operator runs
  `Bootstrap-PostDeploy.ps1` with explicit, typed confirmation of the tenant-mutating steps that
  follow.
- **The Key Vault denies public network access from the moment it is created.** This is correct;
  every later script reaches it only through the private endpoint.
