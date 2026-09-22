import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  loadCbaClientCertificate,
  receiptSha256Pattern,
} from './Get-CbaCredentialsFromKeyVault.mjs';

const execFileAsync = promisify(execFile);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.dirname(scriptDirectory);
const certificateOrigin = 'https://certauth.login.microsoftonline.com';
const privateEndpointIp = ['10', '42', '0', '70'].join('.');
const runnerIp = ['10', '42', '0', '5'].join('.');
const runnerSubnetCidr = `${['10', '42', '0', '0'].join('.')}/26`;

const encodeJwt = (payload) => [
  Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify(payload)).toString('base64url'),
  '',
].join('.');

const successfulJsonResponse = (value) => ({
  ok: true,
  status: 200,
  json: async () => value,
});

await assert.rejects(
  loadCbaClientCertificate({
    environment: {},
    origin: certificateOrigin,
  }),
  /CBA_CERTIFICATE_SOURCE/u,
);

const localPfx = Buffer.from('local-pfx');
const localCredential = await loadCbaClientCertificate({
  environment: {
    CBA_CERTIFICATE_SOURCE: 'file',
    CBA_PFX_PATH: 'virtual-client.pfx',
    CBA_PFX_PASSPHRASE: 'local-passphrase',
  },
  origin: certificateOrigin,
  dependencies: {
    readFileImpl: async (filePath) => {
      assert.equal(filePath, 'virtual-client.pfx');
      return Buffer.from(localPfx);
    },
  },
});
assert.equal(localCredential.source, 'file');
assert.deepEqual(localCredential.clientCertificate.pfx, localPfx);
localCredential.dispose();
assert.ok(
  localCredential.clientCertificate.pfx.every((value) => value === 0),
  'dispose() must overwrite the JavaScript PFX buffer.',
);

const githubSha = 'a'.repeat(40);
const workflowRef =
  'owner/repo/.github/workflows/entra-cba-playwright-poc.yml@refs/heads/main';
const cloudEnvironment = {
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request-token',
  ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.example.invalid/token',
  AZURE_CLIENT_ID: 'workload-client',
  AZURE_TENANT_ID: 'test-tenant',
  CBA_CERTIFICATE_SOURCE: 'key-vault-oidc',
  CBA_EXPECTED_OIDC_SUBJECT:
    'repo:owner/repo:environment:entra-cba-poc',
  CBA_EXPECTED_PRIVATE_ENDPOINT_IP: privateEndpointIp,
  CBA_EXPECTED_RUNNER_SUBNET_CIDR: runnerSubnetCidr,
  CBA_PFX_PASSPHRASE_SECRET_NAME: 'cba-passphrase',
  CBA_PFX_SECRET_NAME: 'cba-pfx',
  CBA_RUNNER_LABEL: 'entra-cba-test-label',
  CBA_VERIFICATION_ID: 'test-verification',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_REPOSITORY: 'owner/repo',
  GITHUB_RUN_ID: '123456',
  GITHUB_SHA: githubSha,
  GITHUB_WORKFLOW_REF: workflowRef,
  GITHUB_WORKFLOW_SHA: githubSha,
  KEY_VAULT_NAME: 'test-vault',
  RUNNER_ARCH: 'X64',
  RUNNER_ENVIRONMENT: 'self-hosted',
  RUNNER_NAME: 'test-runner',
  RUNNER_OS: 'Linux',
};
const oidcToken = encodeJwt({
  iss: 'https://token.actions.githubusercontent.com',
  aud: 'api://AzureADTokenExchange',
  sub: cloudEnvironment.CBA_EXPECTED_OIDC_SUBJECT,
  repository: cloudEnvironment.GITHUB_REPOSITORY,
  run_id: cloudEnvironment.GITHUB_RUN_ID,
  sha: cloudEnvironment.GITHUB_SHA,
  environment: 'entra-cba-poc',
  runner_environment: 'self-hosted',
  workflow_ref: workflowRef,
  workflow_sha: githubSha,
  ref: cloudEnvironment.GITHUB_REF,
  event_name: 'workflow_dispatch',
});
const expectedPfx = Buffer.from('synthetic-pfx-for-provider-contract');
const expires = Math.floor(Date.now() / 1000) + 3600;
let validatedPfx = false;
let writtenReceipt;
const fetchedUrls = [];
const fetchImpl = async (input, options = {}) => {
  const url = String(input);
  fetchedUrls.push(url);
  if (url.startsWith(cloudEnvironment.ACTIONS_ID_TOKEN_REQUEST_URL)) {
    assert.equal(
      new URL(url).searchParams.get('audience'),
      'api://AzureADTokenExchange',
    );
    assert.equal(
      options.headers.Authorization,
      `Bearer ${cloudEnvironment.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
    );
    return successfulJsonResponse({ value: oidcToken });
  }
  if (url.includes('/oauth2/v2.0/token')) {
    assert.equal(options.method, 'POST');
    assert.equal(options.body.get('client_assertion'), oidcToken);
    return successfulJsonResponse({ access_token: 'vault-access-token' });
  }
  if (url.includes('/secrets/cba-pfx?')) {
    return successfulJsonResponse({
      value: expectedPfx.toString('base64'),
      contentType: 'application/x-pkcs12-base64',
      attributes: { enabled: true, exp: expires },
    });
  }
  if (url.includes('/secrets/cba-passphrase?')) {
    return successfulJsonResponse({
      value: 'cloud-passphrase',
      contentType: 'text/plain',
      attributes: { enabled: true, exp: expires },
    });
  }
  throw new Error(`Unexpected test URL '${url}'.`);
};

const cloudCredential = await loadCbaClientCertificate({
  environment: cloudEnvironment,
  origin: certificateOrigin,
  dependencies: {
    fetchImpl,
    lookupImpl: async () => [
      { address: privateEndpointIp, family: 4 },
    ],
    networkInterfacesImpl: () => ({
      eth0: [
        {
          address: runnerIp,
          netmask: ['255', '255', '255', '192'].join('.'),
          family: 'IPv4',
          mac: '00:00:00:00:00:00',
          internal: false,
          cidr: `${runnerIp}/26`,
          scopeid: undefined,
        },
      ],
    }),
    readFileImpl: async () => {
      throw new Error('Cloud mode must not read a credential file.');
    },
    validatePfxImpl: async (pfx, passphrase) => {
      assert.deepEqual(pfx, expectedPfx);
      assert.equal(passphrase, 'cloud-passphrase');
      validatedPfx = true;
    },
    writeReceiptImpl: async (receipt) => {
      writtenReceipt = receipt;
    },
  },
});

assert.equal(cloudCredential.source, 'key-vault-oidc');
assert.ok(validatedPfx, 'Cloud mode must validate the in-memory PFX.');
assert.equal(fetchedUrls.length, 4);
assert.deepEqual(cloudCredential.clientCertificate.pfx, expectedPfx);
assert.equal(writtenReceipt.schemaVersion, 3);
assert.deepEqual(writtenReceipt.credentialHandling, {
  provider: 'key-vault-oidc',
  transport: 'memory-only',
  credentialFilesWritten: false,
});
assert.match(writtenReceipt.receiptSha256, receiptSha256Pattern);
assert.equal(
  writtenReceipt.runner.privateIpv4InExpectedSubnetSha256,
  createHash('sha256')
    .update(JSON.stringify([runnerIp]), 'utf8')
    .digest('hex'),
);

const receiptDirectory = await mkdtemp(
  path.join(tmpdir(), 'entra-cba-receipt-test-'),
);
try {
  const identityReceipt = {
    schemaVersion: 3,
    verifiedAt: new Date().toISOString(),
    verificationIdSha256: 'b'.repeat(64),
    githubRunId: cloudEnvironment.GITHUB_RUN_ID,
    githubSha,
    identitySha256: 'c'.repeat(64),
  };
  await Promise.all([
    writeFile(
      path.join(receiptDirectory, 'cba-feasibility.json'),
      JSON.stringify(identityReceipt),
      'utf8',
    ),
    writeFile(
      path.join(receiptDirectory, 'runner-network.json'),
      JSON.stringify(writtenReceipt),
      'utf8',
    ),
  ]);
  const privacyResult = await execFileAsync(
    process.execPath,
    [
      path.join(scriptDirectory, 'Test-CiReceiptPrivacy.mjs'),
      receiptDirectory,
    ],
    { cwd: projectDirectory },
  );
  assert.match(privacyResult.stdout, /CI_RECEIPT_PRIVACY_PASS/u);
} finally {
  await rm(receiptDirectory, { recursive: true, force: true });
}

cloudCredential.dispose();
assert.ok(
  cloudCredential.clientCertificate.pfx.every((value) => value === 0),
  'dispose() must overwrite the cloud JavaScript PFX buffer.',
);

await assert.rejects(
  loadCbaClientCertificate({
    environment: {
      ...cloudEnvironment,
      CBA_PFX_PATH: 'forbidden.pfx',
    },
    origin: certificateOrigin,
  }),
  /rejects legacy environment variable 'CBA_PFX_PATH'/u,
);

console.log(
  'CBA_CREDENTIAL_PROVIDER_PASS '
  + 'sources=2 cloudCredentialFiles=0 receiptSchema=3',
);
