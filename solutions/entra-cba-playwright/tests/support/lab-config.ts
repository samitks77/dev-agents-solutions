const required = (name: string): string => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Required environment variable '${name}' is not set.`);
  }
  return value;
};

export type LabConfig = {
  appUrl: string;
  signInCorrelationId?: string;
  tenantId: string;
  testObjectId: string;
  testUsername: string;
};

export const getLabConfig = (): LabConfig => {
  const signInCorrelationId = process.env.CBA_SIGN_IN_CORRELATION_ID?.trim();
  if (signInCorrelationId && !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(signInCorrelationId)) {
    throw new Error("'CBA_SIGN_IN_CORRELATION_ID' must be a version-4 UUID.");
  }

  return {
    appUrl: required('CBA_APP_URL'),
    signInCorrelationId: signInCorrelationId || undefined,
    tenantId: required('CBA_TENANT_ID'),
    testObjectId: required('CBA_TEST_OBJECT_ID'),
    testUsername: required('CBA_TEST_USERNAME'),
  };
};
