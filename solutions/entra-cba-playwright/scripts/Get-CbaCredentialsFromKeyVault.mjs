import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import path from 'node:path';

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Required environment variable '${name}' is not set.`);
  }
  return value;
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const fetchJson = async (url, options, operation) => {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`${operation} failed with HTTP ${response.status}.`);
  }
  return response.json();
};

const decodeJwtPayload = (token) => {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('GitHub OIDC token is not a three-part JWT.');
  }
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
};

const ipv4ToNumber = (address) => {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    throw new Error(`'${address}' is not a valid IPv4 address.`);
  }
  return octets.reduce((value, octet) => (value * 256) + octet, 0);
};

const isAddressInCidr = (address, cidr) => {
  const [network, prefixText] = cidr.split('/');
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`'${cidr}' is not a valid IPv4 CIDR.`);
  }
  const blockSize = 2 ** (32 - prefix);
  return Math.floor(ipv4ToNumber(address) / blockSize) === Math.floor(ipv4ToNumber(network) / blockSize);
};

const tenantId = required('AZURE_TENANT_ID');
const clientId = required('AZURE_CLIENT_ID');
const vaultName = required('KEY_VAULT_NAME');
const expectedOidcSubject = required('CBA_EXPECTED_OIDC_SUBJECT');
const expectedPrivateEndpointIp = required('CBA_EXPECTED_PRIVATE_ENDPOINT_IP');
const expectedRunnerSubnetCidr = required('CBA_EXPECTED_RUNNER_SUBNET_CIDR');
const pfxSecretName = required('CBA_PFX_SECRET_NAME');
const passphraseSecretName = required('CBA_PFX_PASSPHRASE_SECRET_NAME');
const verificationId = required('CBA_VERIFICATION_ID');
const runnerLabel = required('CBA_RUNNER_LABEL');
const idTokenRequestUrl = required('ACTIONS_ID_TOKEN_REQUEST_URL');
const idTokenRequestToken = required('ACTIONS_ID_TOKEN_REQUEST_TOKEN');
const runnerTemp = required('RUNNER_TEMP');
const runnerName = required('RUNNER_NAME');
const runnerOs = required('RUNNER_OS');
const runnerArch = required('RUNNER_ARCH');
const githubRepository = required('GITHUB_REPOSITORY');
const githubRunId = required('GITHUB_RUN_ID');
const githubSha = required('GITHUB_SHA');
const githubEnvironment = required('GITHUB_ENV');

if (!/^[a-zA-Z0-9-]{3,24}$/.test(vaultName)) {
  throw new Error(`Key Vault name '${vaultName}' is invalid.`);
}
for (const [label, value] of [
  ['PFX secret', pfxSecretName],
  ['passphrase secret', passphraseSecretName],
]) {
  if (!/^[a-zA-Z0-9-]{1,127}$/.test(value)) {
    throw new Error(`${label} name '${value}' is invalid.`);
  }
}

ipv4ToNumber(expectedPrivateEndpointIp);
const vaultHost = `${vaultName}.vault.azure.net`;
const resolvedVaultAddresses = [
  ...new Set(
    (await lookup(vaultHost, { all: true, family: 4, verbatim: true }))
      .map(({ address }) => address),
  ),
].sort();
if (resolvedVaultAddresses.length !== 1 || resolvedVaultAddresses[0] !== expectedPrivateEndpointIp) {
  throw new Error(`Key Vault DNS did not resolve exclusively to '${expectedPrivateEndpointIp}'.`);
}

const runnerPrivateAddresses = [
  ...new Set(
    Object.values(networkInterfaces())
      .flat()
      .filter((address) => address && address.family === 'IPv4' && !address.internal)
      .map(({ address }) => address),
  ),
].sort();
const runnerPrivateAddressesInExpectedSubnet = runnerPrivateAddresses.filter(
  (address) => isAddressInCidr(address, expectedRunnerSubnetCidr),
);
if (runnerPrivateAddressesInExpectedSubnet.length !== 1) {
  throw new Error(`Runner does not have exactly one private address in '${expectedRunnerSubnetCidr}'.`);
}

const oidcUrl = new URL(idTokenRequestUrl);
oidcUrl.searchParams.set('audience', 'api://AzureADTokenExchange');
const oidc = await fetchJson(
  oidcUrl,
  {
    headers: {
      authorization: `Bearer ${idTokenRequestToken}`,
    },
  },
  'GitHub OIDC token request',
);
if (typeof oidc.value !== 'string' || !oidc.value) {
  throw new Error('GitHub OIDC response did not contain a token.');
}
const oidcClaims = decodeJwtPayload(oidc.value);
const oidcAudiences = Array.isArray(oidcClaims.aud) ? oidcClaims.aud : [oidcClaims.aud];
if (
  oidcClaims.iss !== 'https://token.actions.githubusercontent.com'
  || oidcClaims.sub !== expectedOidcSubject
  || !oidcAudiences.includes('api://AzureADTokenExchange')
  || oidcClaims.repository !== githubRepository
  || String(oidcClaims.run_id) !== githubRunId
  || oidcClaims.sha !== githubSha
  || oidcClaims.runner_environment !== 'self-hosted'
) {
  throw new Error('GitHub OIDC claims do not match the exact repository, environment, run, revision, and runner type.');
}

const tokenBody = new URLSearchParams({
  client_assertion: oidc.value,
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  client_id: clientId,
  grant_type: 'client_credentials',
  scope: 'https://vault.azure.net/.default',
});
const azureToken = await fetchJson(
  `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`,
  {
    body: tokenBody,
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    method: 'POST',
  },
  'Microsoft Entra workload token exchange',
);
if (typeof azureToken.access_token !== 'string' || !azureToken.access_token) {
  throw new Error('Microsoft Entra token response did not contain an access token.');
}

const getSecret = async (name, expectedContentType) => {
  const secret = await fetchJson(
    `https://${vaultName}.vault.azure.net/secrets/${encodeURIComponent(name)}?api-version=7.4`,
    {
      headers: {
        authorization: `Bearer ${azureToken.access_token}`,
      },
    },
    `Key Vault read for '${name}'`,
  );
  if (typeof secret.value !== 'string' || !secret.value) {
    throw new Error(`Key Vault secret '${name}' is empty.`);
  }
  if (secret.contentType !== expectedContentType) {
    throw new Error(
      `Key Vault secret '${name}' has content type '${secret.contentType}', not '${expectedContentType}'.`,
    );
  }
  if (secret.attributes?.enabled === false) {
    throw new Error(`Key Vault secret '${name}' is disabled.`);
  }
  if (secret.attributes?.exp && secret.attributes.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error(`Key Vault secret '${name}' is expired.`);
  }
  return secret.value;
};

const [pfxBase64, passphrase] = await Promise.all([
  getSecret(pfxSecretName, 'application/x-pkcs12-base64'),
  getSecret(passphraseSecretName, 'text/plain'),
]);

const normalizedPfx = pfxBase64.replace(/\s+/gu, '');
if (!/^[a-zA-Z0-9+/]+={0,2}$/.test(normalizedPfx)) {
  throw new Error('The PFX secret is not valid base64.');
}
const pfx = Buffer.from(normalizedPfx, 'base64');
if (pfx.length < 512) {
  throw new Error('The decoded PFX is unexpectedly small.');
}

const runtimeDirectory = path.join(runnerTemp, 'entra-cba');
const pfxPath = path.join(runtimeDirectory, 'client.pfx');
const passphrasePath = path.join(runtimeDirectory, 'passphrase.txt');
await mkdir(runtimeDirectory, { mode: 0o700, recursive: true });
await Promise.all([
  writeFile(pfxPath, pfx, { mode: 0o600 }),
  writeFile(passphrasePath, passphrase, { mode: 0o600 }),
]);
await Promise.all([
  chmod(runtimeDirectory, 0o700),
  chmod(pfxPath, 0o600),
  chmod(passphrasePath, 0o600),
]);

await writeFile(
  githubEnvironment,
  `CBA_PFX_PATH=${pfxPath}\nCBA_PFX_PASSPHRASE_PATH=${passphrasePath}\n`,
  { flag: 'a' },
);

const receiptDirectory = path.resolve(process.cwd(), '.artifacts', 'receipts');
await mkdir(receiptDirectory, { mode: 0o700, recursive: true });
const networkReceipt = {
  azure: {
    keyVaultHostSha256: sha256(vaultHost),
    keyVaultRead: 'succeeded',
    privateEndpointIpSha256: sha256(expectedPrivateEndpointIp),
    resolvedVaultIpv4AddressCount: resolvedVaultAddresses.length,
    resolvedVaultIpv4AddressSha256: sha256(resolvedVaultAddresses[0]),
    runnerSubnetCidrSha256: sha256(expectedRunnerSubnetCidr),
  },
  github: {
    oidcAudience: 'api://AzureADTokenExchange',
    oidcIssuer: oidcClaims.iss,
    oidcSubjectSha256: sha256(oidcClaims.sub),
    repository: githubRepository,
    runId: githubRunId,
    sha: githubSha,
  },
  runner: {
    architecture: runnerArch,
    environment: oidcClaims.runner_environment,
    labelSha256: sha256(runnerLabel),
    nameSha256: sha256(runnerName),
    os: runnerOs,
    privateIpv4AddressCount: runnerPrivateAddresses.length,
    privateIpv4InExpectedSubnetCount: runnerPrivateAddressesInExpectedSubnet.length,
    privateIpv4InExpectedSubnetSha256: sha256(
      JSON.stringify(runnerPrivateAddressesInExpectedSubnet),
    ),
  },
  schemaVersion: 2,
  verificationIdSha256: sha256(verificationId),
  verifiedAt: new Date().toISOString(),
};
const receiptSha256 = createHash('sha256')
  .update(JSON.stringify(networkReceipt))
  .digest('hex');
await writeFile(
  path.join(receiptDirectory, 'runner-network.json'),
  `${JSON.stringify({ ...networkReceipt, receiptSha256 }, null, 2)}\n`,
  { encoding: 'utf8', mode: 0o600 },
);

console.log(`Retrieved and decoded the CBA PFX into '${runtimeDirectory}'.`);
console.log('Verified GitHub OIDC, ACI runner subnet, private DNS, and Key Vault private access.');
