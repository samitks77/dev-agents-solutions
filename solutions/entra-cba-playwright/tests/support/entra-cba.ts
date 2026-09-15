import { expect, type Locator, type Page } from '@playwright/test';
import type { LabConfig } from './lab-config.js';

const clickWhenVisible = async (locator: Locator): Promise<boolean> => {
  if (await locator.isVisible()) {
    await locator.click();
    return true;
  }
  return false;
};

export const completeEntraCbaSignIn = async (
  page: Page,
  lab: LabConfig,
  timeoutMilliseconds = 75_000,
): Promise<void> => {
  const applicationOrigin = new URL(lab.appUrl).origin;
  const signInUrl = new URL(lab.appUrl);
  if (lab.signInCorrelationId) {
    signInUrl.searchParams.set('correlationId', lab.signInCorrelationId);
  }
  await page.goto(signInUrl.href, { waitUntil: 'domcontentloaded' });
  await expect(page.getByTestId('sign-in')).toBeVisible();
  await page.getByTestId('sign-in').click();

  const deadline = Date.now() + timeoutMilliseconds;
  let usernameSubmitted = false;
  let signInOptionsSelected = false;
  let certificateSelected = false;
  let staySignedInAnswered = false;

  while (Date.now() < deadline) {
    const currentUrl = new URL(page.url());
    if (currentUrl.origin === applicationOrigin) {
      const authenticationState = page.getByTestId('auth-status');
      if ((await authenticationState.getAttribute('data-state')) === 'authenticated') {
        return;
      }
    }

    const noCertificateDetected = page.getByRole('heading', {
      name: /no certificate detected/i,
    });
    if (await noCertificateDetected.isVisible()) {
      throw new Error('Entra CBA failed: No certificate detected.');
    }

    const conditionalAccessFailure = page
      .getByText(
        /AADSTS53003|access has been blocked by Conditional Access|authentication strength|does not meet the criteria to access|multifactor authentication is required|credential used is not supported/i,
      )
      .first();
    if (await conditionalAccessFailure.isVisible()) {
      throw new Error(`Entra Conditional Access rejected the sign-in: ${await conditionalAccessFailure.innerText()}`);
    }

    const username = page.locator('input[name="loginfmt"], input[type="email"]').first();
    if (!usernameSubmitted && await username.isVisible()) {
      await username.fill(lab.testUsername);
      const next = page.locator('#idSIButton9, input[type="submit"]').first();
      if (!await clickWhenVisible(next)) {
        throw new Error('The Entra username page did not expose a Next button.');
      }
      usernameSubmitted = true;
      await page.waitForTimeout(500);
      continue;
    }

    const certificate = page
      .locator('#idA_PWD_Certificate')
      .or(page.getByText(/use a certificate or smart card/i))
      .first();
    if (!certificateSelected && await clickWhenVisible(certificate)) {
      certificateSelected = true;
      await page.waitForTimeout(500);
      continue;
    }

    const signInOptions = page
      .locator('#idA_PWD_SwitchToCredPicker')
      .or(page.getByText(/sign-in options/i))
      .first();
    if (!signInOptionsSelected && await clickWhenVisible(signInOptions)) {
      signInOptionsSelected = true;
      await page.waitForTimeout(500);
      continue;
    }

    const staySignedInNo = page.locator('#idBtn_Back').first();
    if (!staySignedInAnswered && await clickWhenVisible(staySignedInNo)) {
      staySignedInAnswered = true;
      await page.waitForTimeout(500);
      continue;
    }

    await page.waitForTimeout(250);
  }

  throw new Error(
    `Entra CBA did not return to '${applicationOrigin}' within ${timeoutMilliseconds} ms; last URL: '${page.url()}'.`,
  );
};

export const expectExpectedIdentity = async (page: Page, lab: LabConfig): Promise<void> => {
  await expect(page.getByTestId('auth-status')).toHaveAttribute('data-state', 'authenticated');
  await expect(page.getByTestId('username')).toHaveText(lab.testUsername, { ignoreCase: true });
  await expect(page.getByTestId('tenant-id')).toHaveText(lab.tenantId, { ignoreCase: true });
  await expect(page.getByTestId('object-id')).toHaveText(lab.testObjectId, { ignoreCase: true });
};
