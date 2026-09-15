import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices, type PlaywrightTestConfig } from '@playwright/test';

const labRoot = path.dirname(fileURLToPath(import.meta.url));
const environmentFile = path.join(labRoot, '.env');
if (existsSync(environmentFile)) {
  process.loadEnvFile(environmentFile);
}

const requiredEnvironmentVariable = (name: string): string => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Required environment variable '${name}' is not set.`);
  }
  return value;
};

const applicationUrl = requiredEnvironmentVariable('CBA_APP_URL');
const certificateOrigin =
  process.env.CBA_CERTAUTH_ORIGIN?.trim() || 'https://certauth.login.microsoftonline.com';
const pfxPath = path.resolve(requiredEnvironmentVariable('CBA_PFX_PATH'));
const passphrasePath = process.env.CBA_PFX_PASSPHRASE_PATH?.trim();
const passphrase = process.env.CBA_PFX_PASSPHRASE ?? (
  passphrasePath ? readFileSync(path.resolve(passphrasePath), 'utf8') : undefined
);
if (!passphrase) {
  throw new Error(
    "Set 'CBA_PFX_PASSPHRASE' or 'CBA_PFX_PASSPHRASE_PATH' to the PFX passphrase.",
  );
}

if (!existsSync(pfxPath)) {
  throw new Error(`The PFX file '${pfxPath}' does not exist.`);
}

for (const origin of [applicationUrl, certificateOrigin]) {
  const url = new URL(origin);
  if (url.protocol !== 'https:') {
    throw new Error(`'${origin}' must use HTTPS.`);
  }
}

const clientCertificate = {
  origin: certificateOrigin,
  passphrase,
  pfxPath,
};

const config: PlaywrightTestConfig = {
  testDir: path.join(labRoot, 'tests'),
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  timeout: 90_000,
  expect: {
    timeout: 15_000,
  },
  outputDir: path.join(labRoot, '.artifacts', 'test-results'),
  reporter: [['line']],
  use: {
    ...devices['Desktop Chrome'],
    baseURL: applicationUrl,
    clientCertificates: [clientCertificate],
    ignoreHTTPSErrors: false,
    screenshot: 'only-on-failure',
    trace: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'cba-feasibility',
      testMatch: 'cba-feasibility.spec.ts',
    },
    {
      name: 'cba-wrong-origin',
      testMatch: 'cba-wrong-origin.spec.ts',
      use: {
        clientCertificates: [
          {
            ...clientCertificate,
            origin: 'https://wrong-origin.invalid',
          },
        ],
      },
    },
    {
      name: 'cba-auth-strength-positive',
      testMatch: 'cba-auth-strength-positive.spec.ts',
    },
    {
      name: 'cba-auth-strength-negative',
      testMatch: 'cba-auth-strength-negative.spec.ts',
    },
    {
      name: 'session-setup',
      testMatch: 'session.setup.ts',
    },
    {
      name: 'authenticated-session',
      dependencies: ['session-setup'],
      testMatch: 'authenticated-session.spec.ts',
      use: {
        storageState: path.join(labRoot, '.auth', 'cba-user.json'),
      },
    },
  ],
};

export default defineConfig(config);
