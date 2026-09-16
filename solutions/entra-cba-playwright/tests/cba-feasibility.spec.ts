import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { test } from '@playwright/test';
import { completeEntraCbaSignIn, expectExpectedIdentity } from './support/entra-cba.js';
import { getLabConfig } from './support/lab-config.js';

test('authenticates the expected Entra user using CBA', async ({ page }, testInfo) => {
  const lab = getLabConfig();

  await completeEntraCbaSignIn(page, lab);
  await expectExpectedIdentity(page, lab);

  const identity = {
    appUrl: new URL(lab.appUrl).href,
    objectId: lab.testObjectId,
    tenantId: lab.tenantId,
    username: lab.testUsername,
  };
  const receiptDirectory = path.resolve(process.cwd(), '.artifacts', 'receipts');
  const verificationId = process.env.CBA_VERIFICATION_ID;
  await mkdir(receiptDirectory, { recursive: true });
  await writeFile(
    path.join(receiptDirectory, 'cba-feasibility.json'),
    `${JSON.stringify({
      schemaVersion: 3,
      githubRunId: process.env.GITHUB_RUN_ID ?? null,
      githubSha: process.env.GITHUB_SHA ?? null,
      identitySha256: createHash('sha256').update(JSON.stringify(identity)).digest('hex'),
      verificationIdSha256: verificationId
        ? createHash('sha256').update(verificationId).digest('hex')
        : null,
      verifiedAt: new Date().toISOString(),
    }, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );

  if (process.env.CBA_SHOW_PROOF === 'true') {
    const screenshotPath = testInfo.outputPath('authenticated-identity.png');
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`CBA_PROOF_READY ${page.url()} ${screenshotPath}`);
    await page.pause();
  }
});
