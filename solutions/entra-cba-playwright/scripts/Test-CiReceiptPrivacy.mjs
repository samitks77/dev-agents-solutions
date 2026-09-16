import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

const receiptDirectory = path.resolve(
  process.argv[2] ?? path.join(process.cwd(), '.artifacts', 'receipts'),
);
const expectedFiles = ['cba-feasibility.json', 'runner-network.json'];
const sha256Pattern = /^[a-f0-9]{64}$/u;

const exactKeys = (value, expected, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is not an object.`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(required)) {
    throw new Error(`${label} contains unexpected or missing properties.`);
  }
};

const readReceipt = async (name) => {
  const filePath = path.join(receiptDirectory, name);
  const details = await stat(filePath);
  if (!details.isFile() || details.size === 0 || details.size > 32 * 1024) {
    throw new Error(`Receipt '${name}' is empty, not a file, or exceeds 32 KiB.`);
  }
  return JSON.parse(await readFile(filePath, 'utf8'));
};

const entries = (await readdir(receiptDirectory)).sort();
if (JSON.stringify(entries) !== JSON.stringify(expectedFiles)) {
  throw new Error('The receipt directory does not contain exactly the two allowed files.');
}

const identity = await readReceipt('cba-feasibility.json');
exactKeys(
  identity,
  [
    'githubRunId',
    'githubSha',
    'identitySha256',
    'schemaVersion',
    'verificationIdSha256',
    'verifiedAt',
  ],
  'Identity receipt',
);
if (
  identity.schemaVersion !== 3
  || !/^\d+$/u.test(String(identity.githubRunId))
  || !/^[a-f0-9]{40}$/u.test(identity.githubSha)
  || !sha256Pattern.test(identity.identitySha256)
  || !sha256Pattern.test(identity.verificationIdSha256)
  || Number.isNaN(Date.parse(identity.verifiedAt))
) {
  throw new Error('Identity receipt values do not satisfy the public schema.');
}

const network = await readReceipt('runner-network.json');
exactKeys(
  network,
  [
    'azure',
    'github',
    'receiptSha256',
    'runner',
    'schemaVersion',
    'verificationIdSha256',
    'verifiedAt',
  ],
  'Network receipt',
);
exactKeys(
  network.azure,
  [
    'keyVaultHostSha256',
    'keyVaultRead',
    'privateEndpointIpSha256',
    'resolvedVaultIpv4AddressCount',
    'resolvedVaultIpv4AddressSha256',
    'runnerSubnetCidrSha256',
  ],
  'Network receipt Azure section',
);
exactKeys(
  network.github,
  ['oidcAudience', 'oidcIssuer', 'oidcSubjectSha256', 'repository', 'runId', 'sha'],
  'Network receipt GitHub section',
);
exactKeys(
  network.runner,
  [
    'architecture',
    'environment',
    'labelSha256',
    'nameSha256',
    'os',
    'privateIpv4AddressCount',
    'privateIpv4InExpectedSubnetCount',
    'privateIpv4InExpectedSubnetSha256',
  ],
  'Network receipt runner section',
);
const committedHashes = [
  network.receiptSha256,
  network.verificationIdSha256,
  network.azure.keyVaultHostSha256,
  network.azure.privateEndpointIpSha256,
  network.azure.resolvedVaultIpv4AddressSha256,
  network.azure.runnerSubnetCidrSha256,
  network.github.oidcSubjectSha256,
  network.runner.labelSha256,
  network.runner.nameSha256,
  network.runner.privateIpv4InExpectedSubnetSha256,
];
if (
  network.schemaVersion !== 2
  || committedHashes.some((value) => !sha256Pattern.test(value))
  || network.azure.keyVaultRead !== 'succeeded'
  || network.azure.resolvedVaultIpv4AddressCount !== 1
  || network.github.oidcAudience !== 'api://AzureADTokenExchange'
  || network.github.oidcIssuer !== 'https://token.actions.githubusercontent.com'
  || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(network.github.repository)
  || !/^\d+$/u.test(String(network.github.runId))
  || !/^[a-f0-9]{40}$/u.test(network.github.sha)
  || network.runner.architecture !== 'X64'
  || network.runner.environment !== 'self-hosted'
  || network.runner.os !== 'Linux'
  || !Number.isInteger(network.runner.privateIpv4AddressCount)
  || network.runner.privateIpv4AddressCount < 1
  || network.runner.privateIpv4InExpectedSubnetCount !== 1
  || Number.isNaN(Date.parse(network.verifiedAt))
) {
  throw new Error('Network receipt values do not satisfy the public schema.');
}
const { receiptSha256, ...networkWithoutReceiptHash } = network;
const calculatedReceiptSha256 = createHash('sha256')
  .update(JSON.stringify(networkWithoutReceiptHash))
  .digest('hex');
if (receiptSha256 !== calculatedReceiptSha256) {
  throw new Error('Network receipt self-hash does not match its allowlisted content.');
}

const serializedReceipts = JSON.stringify({ identity, network });
const forbiddenPatterns = [
  ['GUID', /\b[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\b/iu],
  ['email or UPN', /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu],
  ['IPv4 address or CIDR', /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?![\d.])/u],
  ['Azure subscription resource ID', /\/subscriptions\//iu],
  ['deployed Key Vault hostname', /\.vault\.azure\.net/iu],
  ['deployed Static Web Apps hostname', /\.azurestaticapps\.net/iu],
];
for (const [label, pattern] of forbiddenPatterns) {
  if (pattern.test(serializedReceipts)) {
    throw new Error(`Receipts contain a forbidden raw ${label}.`);
  }
}

console.log('CI_RECEIPT_PRIVACY_PASS files=2 rawDeploymentIdentifiers=0');
