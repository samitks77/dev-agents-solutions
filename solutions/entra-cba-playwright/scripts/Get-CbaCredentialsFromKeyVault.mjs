import { createHash } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const oidcAudience = 'api://AzureADTokenExchange';
const oidcIssuer = 'https://token.actions.githubusercontent.com';
const pfxContentType = 'application/x-pkcs12-base64';
const passphraseContentType = 'text/plain';
const sha256Pattern = /^[a-f0-9]{64}$/u;

const required = (environment, name) => {
  const value = environment[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Required environment variable '${name}' is missing.`);
  }
  return value;
};

const hasEnvironmentVariable = (environment, name) =>
  Object.prototype.hasOwnProperty.call(environment, name);

const sha256 = (value) =>
  createHash('sha256').update(String(value), 'utf8').digest('hex');

const decodeJwtPayload = (token) => {
  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new Error('The GitHub OIDC token is not a three-segment JWT.');
  }

  try {
    return JSON.parse(Buffer.from(segments[1], 'base64url').toString('utf8'));
  } catch {
    throw new Error('The GitHub OIDC token payload is not valid JSON.');
  }
};

const ipv4ToNumber = (address) => {
  const octets = address.split('.').map(Number);
  if (
    octets.length !== 4
    || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    throw new Error(`Invalid IPv4 address '${address}'.`);
  }

  return octets.reduce((value, octet) => ((value << 8) | octet) >>> 0, 0);
};

const isAddressInCidr = (address, cidr) => {
  const [network, prefixText, ...extra] = cidr.split('/');
  const prefix = Number(prefixText);
  if (
    extra.length !== 0
    || !Number.isInteger(prefix)
    || prefix < 0
    || prefix > 32
  ) {
    throw new Error(`Invalid IPv4 CIDR '${cidr}'.`);
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToNumber(address) & mask) === (ipv4ToNumber(network) & mask);
};

const fetchJson = async (fetchImpl, url, options, label) => {
  const response = await fetchImpl(url, options);
  if (!response.ok) {
    throw new Error(`${label} failed with HTTP ${response.status}.`);
  }
  return response.json();
};

const assertHttpsUrl = (value, label) => {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} is not a valid URL.`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`${label} must use HTTPS.`);
  }
  if (
    parsed.username
    || parsed.password
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
  ) {
    throw new Error(`${label} must be an HTTPS origin without a path or query.`);
  }
  return parsed;
};

const assertSecret = (secret, expectedContentType, label) => {
  if (!secret || typeof secret !== 'object' || Array.isArray(secret)) {
    throw new Error(`${label} did not return an object.`);
  }
  if (secret.contentType !== expectedContentType) {
    throw new Error(`${label} has an unexpected content type.`);
  }
  if (secret.attributes?.enabled !== true) {
    throw new Error(`${label} is not explicitly enabled.`);
  }

  const now = Math.floor(Date.now() / 1000);
  if (
    typeof secret.attributes.nbf === 'number'
    && secret.attributes.nbf > now
  ) {
    throw new Error(`${label} is not active yet.`);
  }
  if (
    typeof secret.attributes.exp !== 'number'
    || secret.attributes.exp <= now
  ) {
    throw new Error(`${label} is expired or has no expiry.`);
  }
  if (typeof secret.value !== 'string' || secret.value.length === 0) {
    throw new Error(`${label} has no value.`);
  }
};

const decodeBase64Pfx = (value) => {
  if (
    value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new Error('The Key Vault PFX secret is not canonical base64.');
  }

  const pfx = Buffer.from(value, 'base64');
  if (pfx.length === 0 || pfx.toString('base64') !== value) {
    throw new Error('The Key Vault PFX secret did not decode losslessly.');
  }
  return pfx;
};

export const validatePfxWithOpenSsl = (
  pfx,
  passphrase,
  executable = 'openssl',
) =>
  new Promise((resolve, reject) => {
    const passphraseEnvironmentName = 'CBA_OPENSSL_VALIDATION_PASSPHRASE';
    const childEnvironment = {
      ...process.env,
      [passphraseEnvironmentName]: passphrase,
    };
    const child = spawn(
      executable,
      [
        'pkcs12',
        '-in',
        '-',
        '-passin',
        `env:${passphraseEnvironmentName}`,
        '-noout',
      ],
      {
        env: childEnvironment,
        stdio: ['pipe', 'ignore', 'pipe'],
      },
    );
    delete childEnvironment[passphraseEnvironmentName];
    let settled = false;

    const fail = (message) => {
      if (!settled) {
        settled = true;
        reject(new Error(message));
      }
    };

    child.once('error', () => {
      fail('OpenSSL could not be started to validate the in-memory PFX.');
    });
    child.once('close', (code) => {
      if (settled) {
        return;
      }
      settled = true;
      if (code === 0) {
        resolve();
      } else {
        reject(new Error('OpenSSL rejected the in-memory PFX or passphrase.'));
      }
    });
    child.stdin.once('error', () => {
      fail('OpenSSL closed its PFX input before validation completed.');
    });
    child.stderr.resume();
    child.stdin.end(pfx);
  });

export const buildNetworkReceipt = ({
  environment,
  keyVaultHost,
  privateEndpointIp,
  privateIpv4Addresses,
  privateIpv4InExpectedSubnet,
  resolvedVaultIpv4Addresses,
  runnerSubnetCidr,
  verifiedAt = new Date().toISOString(),
}) => {
  const receiptWithoutHash = {
    schemaVersion: 3,
    verifiedAt,
    verificationIdSha256: sha256(required(environment, 'CBA_VERIFICATION_ID')),
    credentialHandling: {
      provider: 'key-vault-oidc',
      transport: 'memory-only',
      credentialFilesWritten: false,
    },
    github: {
      oidcIssuer,
      oidcAudience,
      oidcSubjectSha256: sha256(required(environment, 'CBA_EXPECTED_OIDC_SUBJECT')),
      repository: required(environment, 'GITHUB_REPOSITORY'),
      runId: required(environment, 'GITHUB_RUN_ID'),
      sha: required(environment, 'GITHUB_SHA'),
    },
    runner: {
      environment: required(environment, 'RUNNER_ENVIRONMENT'),
      os: required(environment, 'RUNNER_OS'),
      architecture: required(environment, 'RUNNER_ARCH'),
      labelSha256: sha256(required(environment, 'CBA_RUNNER_LABEL')),
      nameSha256: sha256(required(environment, 'RUNNER_NAME')),
      privateIpv4AddressCount: privateIpv4Addresses.length,
      privateIpv4InExpectedSubnetCount: privateIpv4InExpectedSubnet.length,
      privateIpv4InExpectedSubnetSha256: sha256(
        JSON.stringify(privateIpv4InExpectedSubnet),
      ),
    },
    azure: {
      keyVaultHostSha256: sha256(keyVaultHost),
      privateEndpointIpSha256: sha256(privateEndpointIp),
      resolvedVaultIpv4AddressCount: resolvedVaultIpv4Addresses.length,
      resolvedVaultIpv4AddressSha256: sha256(
        resolvedVaultIpv4Addresses.join(','),
      ),
      runnerSubnetCidrSha256: sha256(runnerSubnetCidr),
      keyVaultRead: 'succeeded',
    },
  };

  return {
    ...receiptWithoutHash,
    receiptSha256: sha256(JSON.stringify(receiptWithoutHash)),
  };
};

const writeNetworkReceipt = async (receipt) => {
  const receiptDirectory = path.join(
    process.cwd(),
    '.artifacts',
    'receipts',
  );
  const receiptPath = path.join(receiptDirectory, 'runner-network.json');
  await mkdir(receiptDirectory, { recursive: true, mode: 0o700 });
  await writeFile(
    receiptPath,
    `${JSON.stringify(receipt, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );
  await chmod(receiptPath, 0o600);
};

const loadFileCertificate = async (environment, dependencies) => {
  const pfxPath = required(environment, 'CBA_PFX_PATH');
  const passphraseInEnvironment = hasEnvironmentVariable(
    environment,
    'CBA_PFX_PASSPHRASE',
  );
  const passphrasePathInEnvironment = hasEnvironmentVariable(
    environment,
    'CBA_PFX_PASSPHRASE_PATH',
  );
  if (passphraseInEnvironment === passphrasePathInEnvironment) {
    throw new Error(
      'File mode requires exactly one of CBA_PFX_PASSPHRASE or '
      + 'CBA_PFX_PASSPHRASE_PATH.',
    );
  }

  const pfx = await dependencies.readFileImpl(pfxPath);
  const passphrase = passphraseInEnvironment
    ? required(environment, 'CBA_PFX_PASSPHRASE')
    : await dependencies.readFileImpl(
      required(environment, 'CBA_PFX_PASSPHRASE_PATH'),
      'utf8',
    );

  if (!Buffer.isBuffer(pfx) || pfx.length === 0) {
    throw new Error('The local PFX file is empty or unreadable.');
  }
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('The local PFX passphrase is empty or unreadable.');
  }

  return { pfx, passphrase };
};

const loadKeyVaultCertificate = async (environment, dependencies) => {
  for (const name of [
    'CBA_PFX_PATH',
    'CBA_PFX_PASSPHRASE',
    'CBA_PFX_PASSPHRASE_PATH',
  ]) {
    if (hasEnvironmentVariable(environment, name)) {
      throw new Error(
        `Memory-only cloud mode rejects legacy environment variable '${name}'.`,
      );
    }
  }

  const keyVaultName = required(environment, 'KEY_VAULT_NAME');
  if (
    keyVaultName.length < 3
    || keyVaultName.length > 24
    || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])$/u.test(keyVaultName)
  ) {
    throw new Error('KEY_VAULT_NAME is not a valid Azure Key Vault name.');
  }
  const keyVaultHost = `${keyVaultName}.vault.azure.net`;
  const expectedPrivateEndpointIp = required(
    environment,
    'CBA_EXPECTED_PRIVATE_ENDPOINT_IP',
  );
  const expectedRunnerSubnetCidr = required(
    environment,
    'CBA_EXPECTED_RUNNER_SUBNET_CIDR',
  );
  ipv4ToNumber(expectedPrivateEndpointIp);
  isAddressInCidr(expectedPrivateEndpointIp, expectedRunnerSubnetCidr);

  const resolvedVaultIpv4Addresses = [
    ...new Set(
      (
        await dependencies.lookupImpl(
          keyVaultHost,
          { all: true, family: 4 },
        )
      ).map((entry) => entry.address),
    ),
  ].sort();
  if (
    resolvedVaultIpv4Addresses.length !== 1
    || resolvedVaultIpv4Addresses[0] !== expectedPrivateEndpointIp
  ) {
    throw new Error(
      'Key Vault DNS did not resolve exclusively to the expected private endpoint.',
    );
  }

  const privateIpv4Addresses = Object.values(
    dependencies.networkInterfacesImpl(),
  )
    .flatMap((entries) => entries ?? [])
    .filter((entry) => entry.family === 'IPv4' && !entry.internal)
    .map((entry) => entry.address)
    .sort();
  const privateIpv4InExpectedSubnet = privateIpv4Addresses.filter((address) =>
    isAddressInCidr(address, expectedRunnerSubnetCidr));
  if (privateIpv4InExpectedSubnet.length !== 1) {
    throw new Error(
      'The runner does not have exactly one IPv4 address in the expected subnet.',
    );
  }

  const requestUrl = new URL(
    required(environment, 'ACTIONS_ID_TOKEN_REQUEST_URL'),
  );
  requestUrl.searchParams.set('audience', oidcAudience);
  const oidcResponse = await fetchJson(
    dependencies.fetchImpl,
    requestUrl,
    {
      headers: {
        Authorization: `Bearer ${required(
          environment,
          'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
        )}`,
      },
    },
    'GitHub OIDC token request',
  );
  const oidcToken = oidcResponse.value;
  if (typeof oidcToken !== 'string' || oidcToken.length === 0) {
    throw new Error('GitHub did not return an OIDC token.');
  }

  const oidcPayload = decodeJwtPayload(oidcToken);
  const expectedClaims = {
    iss: oidcIssuer,
    aud: oidcAudience,
    sub: required(environment, 'CBA_EXPECTED_OIDC_SUBJECT'),
    repository: required(environment, 'GITHUB_REPOSITORY'),
    run_id: required(environment, 'GITHUB_RUN_ID'),
    sha: required(environment, 'GITHUB_SHA'),
    environment: 'entra-cba-poc',
    runner_environment: 'self-hosted',
    workflow_ref: required(environment, 'GITHUB_WORKFLOW_REF'),
    workflow_sha: required(environment, 'GITHUB_WORKFLOW_SHA'),
    ref: required(environment, 'GITHUB_REF'),
    event_name: 'workflow_dispatch',
  };
  for (const [claim, expected] of Object.entries(expectedClaims)) {
    if (String(oidcPayload[claim]) !== expected) {
      throw new Error(`GitHub OIDC claim '${claim}' does not match.`);
    }
  }

  const tokenResponse = await fetchJson(
    dependencies.fetchImpl,
    `https://login.microsoftonline.com/${encodeURIComponent(
      required(environment, 'AZURE_TENANT_ID'),
    )}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: required(environment, 'AZURE_CLIENT_ID'),
        scope: 'https://vault.azure.net/.default',
        grant_type: 'client_credentials',
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: oidcToken,
      }),
    },
    'Microsoft Entra workload identity exchange',
  );
  const accessToken = tokenResponse.access_token;
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new Error('Microsoft Entra did not return a Key Vault access token.');
  }

  const readSecret = async (secretName, label) =>
    fetchJson(
      dependencies.fetchImpl,
      `https://${keyVaultHost}/secrets/${encodeURIComponent(
        secretName,
      )}?api-version=7.4`,
      { headers: { Authorization: `Bearer ${accessToken}` } },
      label,
    );

  const pfxSecret = await readSecret(
    required(environment, 'CBA_PFX_SECRET_NAME'),
    'Key Vault PFX secret read',
  );
  const passphraseSecret = await readSecret(
    required(environment, 'CBA_PFX_PASSPHRASE_SECRET_NAME'),
    'Key Vault passphrase secret read',
  );
  assertSecret(pfxSecret, pfxContentType, 'Key Vault PFX secret');
  assertSecret(
    passphraseSecret,
    passphraseContentType,
    'Key Vault passphrase secret',
  );

  const pfx = decodeBase64Pfx(pfxSecret.value);
  const passphrase = passphraseSecret.value;
  try {
    await dependencies.validatePfxImpl(pfx, passphrase);
    const receipt = buildNetworkReceipt({
      environment,
      keyVaultHost,
      privateEndpointIp: expectedPrivateEndpointIp,
      privateIpv4Addresses,
      privateIpv4InExpectedSubnet,
      resolvedVaultIpv4Addresses,
      runnerSubnetCidr: expectedRunnerSubnetCidr,
    });
    await dependencies.writeReceiptImpl(receipt);
    return { pfx, passphrase };
  } catch (error) {
    pfx.fill(0);
    throw error;
  }
};

export const loadCbaClientCertificate = async ({
  environment = process.env,
  origin,
  dependencies = {},
} = {}) => {
  const parsedOrigin = assertHttpsUrl(origin, 'CBA certificate origin');
  const source = required(environment, 'CBA_CERTIFICATE_SOURCE');
  const resolvedDependencies = {
    fetchImpl: globalThis.fetch,
    lookupImpl: dnsLookup,
    networkInterfacesImpl: networkInterfaces,
    readFileImpl: readFile,
    validatePfxImpl: validatePfxWithOpenSsl,
    writeReceiptImpl: writeNetworkReceipt,
    ...dependencies,
  };

  let credential;
  if (source === 'file') {
    credential = await loadFileCertificate(environment, resolvedDependencies);
  } else if (source === 'key-vault-oidc') {
    credential = await loadKeyVaultCertificate(
      environment,
      resolvedDependencies,
    );
  } else {
    throw new Error(
      "CBA_CERTIFICATE_SOURCE must be either 'file' or 'key-vault-oidc'.",
    );
  }

  let disposed = false;
  return {
    clientCertificate: {
      origin: parsedOrigin.origin,
      pfx: credential.pfx,
      passphrase: credential.passphrase,
    },
    source,
    dispose: () => {
      if (!disposed) {
        disposed = true;
        credential.pfx.fill(0);
      }
    },
  };
};

export const receiptSha256Pattern = sha256Pattern;
