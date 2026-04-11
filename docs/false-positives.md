# Handling False Positives

Security scanners sometimes flag legitimate code. Here's how to handle it.

## Gitleaks — Secret False Positives

Create `.gitleaks.allowlist.toml`:

```toml
[allowlist]
paths = [
    '''test/fixtures/.*''',
    '''examples/.*''',
]
regexes = [
    '''TEST_API_KEY_.*''',
]

[[allowlist.commits]]
sha = "abc123..."
```

## Semgrep — SAST False Positives

Add inline `nosemgrep` comments:

```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # nosemgrep: python.sql.security.query
```

Or in `.securepipe.yml`:

```yaml
sast:
  skip_rules:
    - "python.sql.security.query"
```

## Trivy — Dependency False Positives

In `.securepipe.yml`:

```yaml
dependencies:
  ignore_cves:
    - CVE-2023-XXXX  # Reason: not applicable, using patched version
```

Or create a `.trivyignore` file:

```
# CVE,Reason
CVE-2023-XXXX,Not applicable - using vendored patch
```

## Hadolint — Dockerfile False Positives

Add inline ignores:

```dockerfile
# hadolint ignore=DL3008
RUN apt-get install -y some-package
```

## General Approach

1. **Don't blanket-ignore** — each suppression should have a reason
2. **Review quarterly** — some false positives become real vulnerabilities
3. **Document why** — add comments explaining the suppression
4. **Minimize suppressions** — fix the issue if possible instead of suppressing