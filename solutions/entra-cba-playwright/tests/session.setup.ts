import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test as setup } from '@playwright/test';
import { completeEntraCbaSignIn, expectExpectedIdentity } from './support/entra-cba.js';
import { getLabConfig } from './support/lab-config.js';

const labRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const authenticationStatePath = path.join(labRoot, '.auth', 'cba-user.json');

setup('creates a reusable application session', async ({ page }) => {
  const lab = getLabConfig();

  await completeEntraCbaSignIn(page, lab);
  await expectExpectedIdentity(page, lab);
  await page.context().storageState({ path: authenticationStatePath, indexedDB: true });
});
