import { expect, test } from '@playwright/test';
import { completeEntraCbaSignIn } from './support/entra-cba.js';
import { getLabConfig } from './support/lab-config.js';

test('single-factor CBA does not satisfy phishing-resistant MFA', async ({ page }, testInfo) => {
  test.skip(
    process.env.RUN_AUTH_STRENGTH_TESTS !== 'true',
    'Enable the isolated Conditional Access policy and use the policy validation script.',
  );

  const lab = getLabConfig();
  await expect(completeEntraCbaSignIn(page, lab, 45_000)).rejects.toThrow(
    /conditional access|authentication strength|does not meet|AADSTS53003|multifactor authentication is required|credential used is not supported/i,
  );
  expect(new URL(page.url()).origin).not.toBe(new URL(lab.appUrl).origin);

  const bodyText = await page.locator('body').innerText();
  expect(bodyText).toMatch(
    /conditional access|authentication strength|does not meet|AADSTS53003|multifactor authentication is required|credential used is not supported/i,
  );

  const screenshotPath = testInfo.outputPath('authentication-strength-rejection.png');
  await page.screenshot({ path: screenshotPath, fullPage: true });
  await testInfo.attach('authentication-strength-rejection', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});
