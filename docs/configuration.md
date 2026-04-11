# SecurePipe Configuration Guide

## Configuration File

Create `.securepipe.yml` in your project root. All settings are optional — SecurePipe uses sensible defaults.

### Global Settings

```yaml
version: "1.0"

settings:
  # Exit with error code on critical findings
  fail_on_critical: true    # default: true
  
  # Exit with error code on high findings  
  fail_on_high: true        # default: true
  
  # Report output format
  report_format: html       # html | json | sarif
  
  # Output directory
  output_dir: securepipe-reports/
```

### Stage Configuration

```yaml
sast:
  enabled: true
  tools: [semgrep, codeql]
  languages: [python, javascript, go, java, dockerfile, yaml]
  # Custom Semgrep rules
  custom_rules: []
  # Skip specific rules
  skip_rules: []

secrets:
  enabled: true
  tools: [gitleaks]
  # Allowlist for known false positives
  allowlist: .gitleaks.allowlist.toml

dependencies:
  enabled: true
  tools: [trivy, owasp-depcheck]
  # CVE whitelist — these won't fail the pipeline
  ignore_cves:
    - CVE-2023-XXXX
  # Ignore dev dependencies
  skip_dev: false

container:
  enabled: true
  tools: [trivy, hadolint]
  image: "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"
  # Only fail on HIGH and CRITICAL
  severity_threshold: HIGH

dast:
  enabled: true
  tools: [zap]
  target_url: "http://localhost:8080"
  # Scan timeout in minutes
  timeout: 30

signing:
  enabled: true
  tools: [cosign]
  registry: "${CI_REGISTRY}"
  # Keyless signing (default) or key-based
  keyless: true

sbom:
  enabled: true
  # cyclonedx | spdx | syft-json
  format: cyclonedx
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECUREPIPE_CONFIG` | `.securepipe.yml` | Config file path |
| `SECUREPIPE_OUTPUT` | `securepipe-reports` | Output directory |
| `SECUREPIPE_FAIL_ON_CRITICAL` | `true` | Fail on critical findings |
| `SECUREPIPE_FAIL_ON_HIGH` | `true` | Fail on high findings |
| `SECUREPIPE_SKIP_SECRETS` | `false` | Skip secrets stage |
| `SECUREPIPE_SKIP_SAST` | `false` | Skip SAST stage |
| `SECUREPIPE_SKIP_DEPS` | `false` | Skip dependency scan |
| `SECUREPIPE_SKIP_CONTAINER` | `false` | Skip container scan |
| `SECUREPIPE_SKIP_DAST` | `false` | Skip DAST stage |
| `SECUREPIPE_SKIP_SIGNING` | `false` | Skip signing stage |
| `SECUREPIPE_SKIP_SBOM` | `false` | Skip SBOM generation |
| `SECUREPIPE_CONTAINER_IMAGE` | — | Image to scan/sign |
| `SECUREPIPE_DAST_URL` | — | Target URL for DAST |

## GitLab CI Setup

### Option 1: Remote include (recommended)

```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/full-pipeline.yml'

variables:
  SECUREPIPE_CONTAINER_IMAGE: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
  SECUREPIPE_DAST_URL: "https://staging.example.com"
```

### Option 2: Local copy

```yaml
include:
  - local: '/securepipe/templates/gitlab/full-pipeline.yml'
```

### Option 3: Individual stages only

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/sast.yml'
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/secrets.yml'
```

## Jenkins Setup

1. Add the shared library to your Jenkins configuration
2. In your Jenkinsfile:

```groovy
@Library('securepipe') _

securePipeFullScan(
    failOnCritical: true,
    containerImage: 'myapp:latest',
    dastUrl: 'https://staging.example.com'
)
```

## Standalone CLI

```bash
# Full scan
./securepipe.sh scan --all

# Specific stages
./securepipe.sh scan --secrets --sast

# With container image
./securepipe.sh scan --container myapp:latest --signing myapp:latest

# Custom output
./securepipe.sh scan --all --output ./my-reports --report html
```