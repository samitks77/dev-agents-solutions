import { test } from '@playwright/test';
import { completeEntraCbaSignIn, expectExpectedIdentity } from './support/entra-cba.js';
import { getLabConfig } from './support/lab-config.js';

test('multifactor CBA satisfies phishing-resistant MFA', async ({ page }) => {
  test.skip(
    process.env.RUN_AUTH_STRENGTH_TESTS !== 'true',
    'Enable the isolated Conditional Access policy and use the policy validation script.',
  );

  const lab = getLabConfig();
  await completeEntraCbaSignIn(page, lab);
  await expectExpectedIdentity(page, lab);
});
