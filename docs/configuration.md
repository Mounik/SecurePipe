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
  report_format: html       # html | json
  
  # Output directory
  output_dir: securepipe-reports/
```

### Stage Configuration

```yaml
sast:
  enabled: true
  tools: [semgrep]
  languages: [python, javascript, go, java, dockerfile, yaml]
  # Custom Semgrep rules (comma-separated or "auto")
  custom_rules: auto
  # Or specify custom rulesets:
  # custom_rules: ["p/python", "p/owasp-top-ten", "path/to/rules.yml"]

secrets:
  enabled: true
  tools: [gitleaks]
  # Allowlist for known false positives
  allowlist: .gitleaks.allowlist.toml

dependencies:
  enabled: true
  tools: [trivy]
  # CVE whitelist — these won't fail the pipeline
  ignore_cves:
    - CVE-2023-XXXX
  # Ignore dev dependencies
  skip_dev: false

container:
  enabled: true
  tools: [trivy, hadolint]
  image: "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"
  # Only report findings at this severity and above
  severity_threshold: HIGH

dast:
  enabled: true
  tools: [zap]
  target_url: "http://localhost:8080"

signing:
  enabled: true
  tools: [cosign]
  # Keyless signing (default) or key-based (requires COSIGN_KEY env var)
  keyless: true

sbom:
  enabled: true
  # cyclonedx
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
| `COSIGN_KEY` | — | Cosign private key for signing |

## CLI Options

```
Usage: securepipe.sh scan [OPTIONS]

Options:
  --all          Run all stages
  --sast         Static analysis
  --secrets      Secrets detection
  --deps         Dependency scanning
  --container IMG  Container scanning
  --dast URL     Dynamic testing
  --signing IMG  Sign container image
  --sbom         Generate SBOM
  --report FMT   Report format (html|json)
  --output DIR   Output directory
  --config FILE  Config file path
  --verbose      Show debug output
```

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

## GitHub Actions Setup

Copy `templates/github/securepipe.yml` into `.github/workflows/` or use it directly:

```yaml
# .github/workflows/securepipe.yml
# See templates/github/securepipe.yml for full configuration
# Set repository variables: SECUREPIPE_CONTAINER_IMAGE, SECUREPIPE_DAST_URL
# Set repository secret: COSIGN_KEY (if signing)
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

# Verbose mode
./securepipe.sh scan --all --verbose
```

## Config Parsing

SecurePipe parses `.securepipe.yml` using:
1. **yq** (preferred) — fast, native YAML processor
2. **python3 + PyYAML** (fallback) — used when yq is not installed

Environment variables always override config file settings.