import { expect, test } from '@playwright/test';
import { completeEntraCbaSignIn } from './support/entra-cba.js';
import { getLabConfig } from './support/lab-config.js';

test('does not authenticate when the client certificate origin is wrong', async ({ page }, testInfo) => {
  test.skip(
    process.env.RUN_NEGATIVE_CBA_TESTS !== 'true',
    'Set RUN_NEGATIVE_CBA_TESTS=true to generate the intentional failed sign-in.',
  );

  const lab = getLabConfig();
  await expect(completeEntraCbaSignIn(page, lab, 30_000)).rejects.toThrow(/no certificate detected/i);
  await expect(page.getByRole('heading', { name: /no certificate detected/i })).toBeVisible();
  expect(new URL(page.url()).origin).not.toBe(new URL(lab.appUrl).origin);

  const screenshotPath = testInfo.outputPath('no-certificate-detected.png');
  await page.screenshot({ path: screenshotPath, fullPage: true });
  await testInfo.attach('wrong-origin-rejection', {
    path: screenshotPath,
    contentType: 'image/png',
  });
  console.log(`CBA_NEGATIVE_PROOF ${page.url()} ${screenshotPath}`);
});
