import { expect, test } from '@playwright/test';
import { expectExpectedIdentity } from './support/entra-cba.js';
import { getLabConfig } from './support/lab-config.js';

test('reuses the authenticated application state without another CBA exchange', async ({ page }) => {
  const lab = getLabConfig();
  const requestedHosts = new Set<string>();
  page.on('request', (request) => {
    requestedHosts.add(new URL(request.url()).hostname);
  });

  await page.goto(lab.appUrl, { waitUntil: 'domcontentloaded' });
  await expectExpectedIdentity(page, lab);

  const certauthHosts = [...requestedHosts].filter(
    (hostname) =>
      hostname === 'certauth.login.microsoftonline.com' ||
      hostname.endsWith('.certauth.login.microsoftonline.com'),
  );
  expect(certauthHosts).toEqual([]);
});
