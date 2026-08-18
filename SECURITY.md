# Security Policy

## Public-release hygiene

Do not commit real subscription IDs, tenant IDs, client IDs, endpoints, keys, tokens, connection strings, certificates, or credential files. Use obvious placeholders in examples, such as `<subscription-id>`, `<tenant-id>`, `<client-id>`, `<endpoint>`, and `<connection-string>`.

If a credential or tenant-specific identifier was ever committed, revoke or rotate any real secret immediately, then scan the full Git history before making the repository public. A history-aware scanner such as gitleaks can be run from a fresh clone:

```bash
gitleaks detect --source . --log-opts="--all" --redact
```

If the history scan finds real credentials, the repository owner should coordinate remediation, including revocation/rotation and any required history cleanup, before publishing.

For solution-specific security expectations, see [`solutions/driftlock-vector/SECURITY.md`](solutions/driftlock-vector/SECURITY.md).
