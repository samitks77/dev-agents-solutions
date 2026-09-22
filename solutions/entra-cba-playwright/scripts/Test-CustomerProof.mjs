import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectDirectory = path.dirname(
  path.dirname(fileURLToPath(import.meta.url)),
);
const jsonPath = path.join(
  projectDirectory,
  'docs',
  'entra-cba-playwright-customer-verification-2026-09-22.json',
);
const pdfPath = path.join(
  projectDirectory,
  'docs',
  'entra-cba-playwright-customer-verification-2026-09-22.pdf',
);
const expectedJsonSha256 =
  'c431869afd66be809a401cb9a5a29708f64242d7025f631afb27163e719ad84f';
const expectedPdfSha256 =
  '13854de491b38f2d5fffd7653c050351efa68cab67197c171c41a8ef3ba1e92f';
const testedCommit = 'fb0771dec58abe5fbc4b2c39325f08c8c356a10d';
const sha256Pattern = /^[a-f0-9]{64}$/u;

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
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

const jsonBytes = await readFile(jsonPath);
if (sha256(jsonBytes) !== expectedJsonSha256) {
  throw new Error('Customer proof JSON does not match its pinned SHA-256.');
}
const proof = JSON.parse(jsonBytes.toString('utf8'));
exactKeys(
  proof,
  [
    'artifactType',
    'browserControls',
    'checks',
    'cleanup',
    'conditionalAccess',
    'generatedAtUtc',
    'independentVerification',
    'privacy',
    'proofSha256',
    'schemaVersion',
    'scope',
    'source',
    'verdict',
    'verification',
  ],
  'Customer proof',
);
exactKeys(
  proof.source,
  [
    'branch',
    'repository',
    'repositoryUrl',
    'solutionPath',
    'testedCommit',
  ],
  'Customer proof source',
);
exactKeys(
  proof.verification,
  [
    'checksFailed',
    'checksPassed',
    'checksTotal',
    'cloudCredentialFilesWritten',
    'credentialProvider',
    'credentialTransport',
    'publicLogPrivacy',
  ],
  'Customer proof verification',
);
exactKeys(
  proof.privacy,
  [
    'credentialsCertificatesOrPassphrasesIncluded',
    'deployedHostnamesOrNetworkAddressesIncluded',
    'subscriptionIdentifiersIncluded',
    'tenantIdentifiersIncluded',
    'userOrObjectIdentifiersIncluded',
    'workflowRunOrCorrelationIdentifiersIncluded',
  ],
  'Customer proof privacy',
);
exactKeys(
  proof.cleanup,
  [
    'ephemeralAciContainerDeleted',
    'ephemeralGitHubRunnerDeregistered',
    'transientEvidenceArtifactDeleted',
  ],
  'Customer proof cleanup',
);

if (
  proof.schemaVersion !== 3
  || proof.artifactType !== 'customer-shareable-sanitized-verification'
  || proof.verdict !== 'PASS'
  || Number.isNaN(Date.parse(proof.generatedAtUtc))
  || proof.source.repository !== 'samitks77/dev-agents-solutions'
  || proof.source.branch !== 'main'
  || proof.source.testedCommit !== testedCommit
  || proof.verification.checksTotal !== 37
  || proof.verification.checksPassed !== 37
  || proof.verification.checksFailed !== 0
  || proof.verification.credentialProvider !== 'key-vault-oidc'
  || proof.verification.credentialTransport !== 'memory-only'
  || proof.verification.cloudCredentialFilesWritten !== false
  || proof.verification.publicLogPrivacy !== 'pass'
  || Object.values(proof.cleanup).some((value) => value !== true)
  || Object.values(proof.privacy).some((value) => value !== false)
  || !Array.isArray(proof.checks)
  || proof.checks.length !== 37
  || proof.checks.some((check) => {
    exactKeys(check, ['name', 'result', 'stage'], 'Customer proof check');
    return (
      typeof check.stage !== 'string'
      || check.stage.length === 0
      || typeof check.name !== 'string'
      || check.name.length === 0
      || check.result !== 'PASS'
    );
  })
) {
  throw new Error('Customer proof values do not satisfy the exact public contract.');
}

const { proofSha256, ...proofWithoutHash } = proof;
if (
  !sha256Pattern.test(proofSha256)
  || proofSha256 !== sha256(JSON.stringify(proofWithoutHash))
) {
  throw new Error('Customer proof self-hash does not match its allowlisted content.');
}

const serializedProof = JSON.stringify(proof);
const forbiddenPatterns = [
  ['GUID', /\b[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\b/iu],
  ['email or UPN', /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu],
  ['IPv4 address or CIDR', /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?(?![\d.])/u],
  ['Azure subscription resource ID', /\/subscriptions\//iu],
  ['deployed Key Vault hostname', /\.vault\.azure\.net/iu],
  ['deployed Static Web Apps hostname', /\.azurestaticapps\.net/iu],
];
for (const [label, pattern] of forbiddenPatterns) {
  if (pattern.test(serializedProof)) {
    throw new Error(`Customer proof contains a forbidden ${label}.`);
  }
}

const pdfDetails = await stat(pdfPath);
const pdfBytes = await readFile(pdfPath);
if (
  !pdfDetails.isFile()
  || pdfDetails.size === 0
  || pdfDetails.size > 5 * 1024 * 1024
  || !pdfBytes.subarray(0, 5).equals(Buffer.from('%PDF-'))
  || sha256(pdfBytes) !== expectedPdfSha256
) {
  throw new Error('Customer proof PDF does not match its bounded pinned artifact.');
}

console.log(
  'CUSTOMER_PROOF_PASS checks=37 identifiers=0 '
  + `jsonSha256=${expectedJsonSha256} pdfSha256=${expectedPdfSha256}`,
);
