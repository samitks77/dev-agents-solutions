import type { ClientCertificate } from '@playwright/test';

export interface CredentialDependencies {
  fetchImpl?: typeof fetch;
  lookupImpl?: (
    hostname: string,
    options: { all: true; family: 4 },
  ) => Promise<Array<{ address: string; family: number }>>;
  networkInterfacesImpl?: () => NodeJS.Dict<import('node:os').NetworkInterfaceInfo[]>;
  readFileImpl?: typeof import('node:fs/promises').readFile;
  validatePfxImpl?: (pfx: Buffer, passphrase: string) => Promise<void>;
  writeReceiptImpl?: (receipt: NetworkReceiptV3) => Promise<void>;
}

export interface NetworkReceiptV3 {
  schemaVersion: 3;
  verifiedAt: string;
  verificationIdSha256: string;
  credentialHandling: {
    provider: 'key-vault-oidc';
    transport: 'memory-only';
    credentialFilesWritten: false;
  };
  github: {
    oidcIssuer: string;
    oidcAudience: string;
    oidcSubjectSha256: string;
    repository: string;
    runId: string;
    sha: string;
  };
  runner: {
    environment: string;
    os: string;
    architecture: string;
    labelSha256: string;
    nameSha256: string;
    privateIpv4AddressCount: number;
    privateIpv4InExpectedSubnetCount: number;
    privateIpv4InExpectedSubnetSha256: string;
  };
  azure: {
    keyVaultHostSha256: string;
    privateEndpointIpSha256: string;
    resolvedVaultIpv4AddressCount: number;
    resolvedVaultIpv4AddressSha256: string;
    runnerSubnetCidrSha256: string;
    keyVaultRead: 'succeeded';
  };
  receiptSha256: string;
}

export interface LoadedCbaClientCertificate {
  clientCertificate: ClientCertificate;
  source: 'file' | 'key-vault-oidc';
  dispose: () => void;
}

export function loadCbaClientCertificate(options: {
  environment?: NodeJS.ProcessEnv;
  origin: string;
  dependencies?: CredentialDependencies;
}): Promise<LoadedCbaClientCertificate>;

export function buildNetworkReceipt(input: {
  environment: NodeJS.ProcessEnv;
  keyVaultHost: string;
  privateEndpointIp: string;
  privateIpv4Addresses: string[];
  privateIpv4InExpectedSubnet: string[];
  resolvedVaultIpv4Addresses: string[];
  runnerSubnetCidr: string;
  verifiedAt?: string;
}): NetworkReceiptV3;

export function validatePfxWithOpenSsl(
  pfx: Buffer,
  passphrase: string,
  executable?: string,
): Promise<void>;

export const receiptSha256Pattern: RegExp;
