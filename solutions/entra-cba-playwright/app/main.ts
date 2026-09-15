import {
  PublicClientApplication,
  type AccountInfo,
  type Configuration,
  type IdTokenClaims,
} from '@azure/msal-browser';

type LabConfiguration = {
  clientId: string;
  redirectUri: string;
  tenantId: string;
  testUsername?: string;
};

declare global {
  interface Window {
    __CBA_CONFIG__?: LabConfiguration;
  }
}

const requiredElement = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Required element '#${id}' is missing.`);
  }
  return element as T;
};

const requireConfiguration = (): LabConfiguration => {
  const configuration = window.__CBA_CONFIG__;
  if (!configuration?.clientId || !configuration.redirectUri || !configuration.tenantId) {
    throw new Error('The runtime application configuration is incomplete.');
  }
  return configuration;
};

const status = requiredElement<HTMLParagraphElement>('status');
const signIn = requiredElement<HTMLButtonElement>('sign-in');
const signOut = requiredElement<HTMLButtonElement>('sign-out');
const claimsPanel = requiredElement<HTMLElement>('claims');
const errorPanel = requiredElement<HTMLElement>('error-panel');
const errorText = requiredElement<HTMLElement>('error');

const setStatus = (message: string, state: string): void => {
  status.textContent = message;
  status.dataset.state = state;
};

const renderAccount = (account: AccountInfo): void => {
  const claims = account.idTokenClaims as IdTokenClaims & {
    oid?: string;
    preferred_username?: string;
    tid?: string;
  };

  const username = claims.preferred_username ?? account.username;
  const tenantId = claims.tid ?? account.tenantId;
  const objectId = claims.oid ?? account.localAccountId;

  document.querySelector<HTMLElement>('[data-testid="username"]')!.textContent = username;
  document.querySelector<HTMLElement>('[data-testid="tenant-id"]')!.textContent = tenantId;
  document.querySelector<HTMLElement>('[data-testid="object-id"]')!.textContent = objectId;

  claimsPanel.hidden = false;
  signIn.hidden = true;
  signOut.hidden = false;
  setStatus('Authenticated', 'authenticated');
};

const renderSignedOut = (): void => {
  claimsPanel.hidden = true;
  signIn.hidden = false;
  signOut.hidden = true;
  setStatus('Not authenticated', 'signed-out');
};

const hasExpectedUnexpiredIdToken = (
  account: AccountInfo,
  lab: LabConfiguration,
): boolean => {
  const claims = account.idTokenClaims as IdTokenClaims & {
    aud?: string;
    preferred_username?: string;
    tid?: string;
  };
  const username = claims.preferred_username ?? account.username;
  return (
    typeof claims.exp === 'number'
    && claims.exp * 1000 > Date.now()
    && claims.aud === lab.clientId
    && (claims.tid ?? account.tenantId).toLowerCase() === lab.tenantId.toLowerCase()
    && (!lab.testUsername || username.toLowerCase() === lab.testUsername.toLowerCase())
  );
};

const requestedCorrelationId = new URL(window.location.href).searchParams.get('correlationId');
if (
  requestedCorrelationId
  && !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    .test(requestedCorrelationId)
) {
  throw new Error('The sign-in correlation identifier is not a valid version-4 UUID.');
}

const renderError = (error: unknown): void => {
  const message = error instanceof Error ? error.message : String(error);
  errorText.textContent = message;
  errorPanel.hidden = false;
  setStatus('Authentication failed', 'error');
  console.error('Authentication failed:', message);
};

const main = async (): Promise<void> => {
  const lab = requireConfiguration();
  const configuration: Configuration = {
    auth: {
      clientId: lab.clientId,
      authority: `https://login.microsoftonline.com/${lab.tenantId}`,
      redirectUri: lab.redirectUri,
      postLogoutRedirectUri: lab.redirectUri,
    },
    cache: {
      cacheLocation: 'localStorage',
    },
  };

  const client = new PublicClientApplication(configuration);
  await client.initialize();

  const redirectResult = await client.handleRedirectPromise();
  const account = redirectResult?.account ?? client.getAllAccounts()[0];
  if (account && hasExpectedUnexpiredIdToken(account, lab)) {
    client.setActiveAccount(account);
    renderAccount(account);
  } else {
    if (account) {
      await client.clearCache({ account });
    }
    renderSignedOut();
  }

  signIn.addEventListener('click', () => {
    void client.loginRedirect({
      correlationId: requestedCorrelationId ?? undefined,
      loginHint: lab.testUsername,
      prompt: 'login',
      scopes: ['openid', 'profile'],
    }).catch(renderError);
  });

  signOut.addEventListener('click', () => {
    void client.logoutRedirect({
      account: client.getActiveAccount() ?? undefined,
    }).catch(renderError);
  });
};

void main().catch(renderError);
