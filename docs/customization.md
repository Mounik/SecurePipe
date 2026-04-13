# Customization Guide

## Custom Semgrep Rules

Add custom rulesets in `.securepipe.yml`:

```yaml
sast:
  custom_rules:
    - p/python
    - p/owasp-top-ten
    - p/security-audit
    - path/to/custom-rules.yml
```

Or use the `SEMGREP_CONFIG` environment variable in CI:

```yaml
# GitLab CI
variables:
  SEMGREP_CONFIG: "p/python,p/owasp-top-ten"
```

## Severity Thresholds

Control which findings cause pipeline failure:

```yaml
settings:
  fail_on_critical: true
  fail_on_high: false

container:
  severity_threshold: HIGH  # Only report HIGH and CRITICAL
```

## Pipeline Stages

You can run individual stages in separate pipelines:

### SAST Only
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/sast.yml'
```

### Secrets Only
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/secrets.yml'
```

## Multi-Project Setup

For monorepos with multiple services:

```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/full-pipeline.yml'

# Override per service
backend:scan:
  extends: .securepipe-sast
  variables:
    SEMGREP_CONFIG: "p/python"
  only:
    changes:
      - backend/**
```

## CVE Whitelisting

Ignore specific CVEs that are false positives for your project:

```yaml
dependencies:
  ignore_cves:
    - CVE-2023-XXXX  # Not applicable — using vendored patch
```

## Docker Image Versions

All scanner images are pinned to specific versions for reproducibility. You can override these in the CLI script by editing the image variables at the top of `securepipe.sh`:

```bash
SEMGREP_IMAGE="returntocorp/semgrep:1.64"
GITLEAKS_IMAGE="zricethezav/gitleaks:8.18"
TRIVY_IMAGE="aquasec/trivy:0.51"
```

## Pre-commit Hooks

Use SecurePipe's pre-commit configuration for local scanning:

```bash
pip install pre-commit
pre-commit install
```

See `.pre-commit-config.yaml` for the available hooks (Gitleaks, Hadolint).