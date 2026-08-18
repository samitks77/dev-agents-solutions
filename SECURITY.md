# Security Policy

## Public-release hygiene

Do not commit real subscription IDs, tenant IDs, client IDs, endpoints, keys, tokens, connection strings, certificates, or credential files. Use obvious placeholders in examples, such as `<subscription-id>`, `<tenant-id>`, `<client-id>`, `<endpoint>`, and `<connection-string>`.

Before making the repository public, run a full-history secret scan from a fresh clone and include all locally available refs:

```bash
gitleaks detect --source . --log-opts="--all" --redact
```

If `gitleaks` is unavailable locally, install it first (for example with Homebrew, Scoop, or official binary release) and re-run the same command. If installation is impossible in your environment, use a fallback scanner (for example `trufflehog git file://.`) and document that fallback's history/ref coverage limitations.

### Interpreting findings safely

- Treat **actual credentials** (keys, secrets, tokens, passwords, private cert/key material, signed URLs, connection strings) as incident-level findings.
- Distinguish **organizational metadata** (subscription IDs, tenant domains/IDs, resource names, GUID app IDs) from credentials. Metadata may still be sensitive and should be minimized, but it is not a revocable credential by itself.
- Do not paste live values into issues, pull requests, or logs. Keep reports redacted.

### Historical credential remediation runbook

If a history-aware scan finds real credentials:

1. Revoke/rotate impacted credentials first.
2. Coordinate a history rewrite using `git filter-repo` or BFG on a maintained branch copy (do not rewrite history ad hoc from an unrelated PR).
3. Force-push rewritten branches/tags and communicate force-push impact to collaborators.
4. Invalidate old local clones/forks and require a fresh clone from rewritten refs.
5. Verify the rewritten history from a fresh clone with:
   ```bash
   gitleaks detect --source . --log-opts="--all" --redact
   ```
6. Only then proceed with public release.

## Preventing future leaks

- CI runs repository secret scanning on push and pull request.
- Developers can run the same local check before commit/push:
  ```bash
  gitleaks detect --source . --log-opts="--all" --redact
  ```
- Optional pre-push hook (local, no credentials required):
  ```bash
  cat > .git/hooks/pre-push <<'EOF'
  #!/usr/bin/env bash
  set -euo pipefail
  gitleaks detect --source . --log-opts="--all" --redact
  EOF
  chmod +x .git/hooks/pre-push
  ```

For solution-specific security expectations, see [`solutions/driftlock-vector/SECURITY.md`](solutions/driftlock-vector/SECURITY.md).
