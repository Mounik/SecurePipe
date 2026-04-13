# SecurePipe
![CI](https://github.com/Mounik/SecurePipe/actions/workflows/ci.yml/badge.svg)

**Production-ready DevSecOps pipeline — drop-in security for any CI/CD**

SecurePipe is a complete, opinionated DevSecOps pipeline template that secures every stage of your software delivery. One configuration file, full security coverage.

## Security Stages

| Stage | Tool | What it detects |
|-------|------|-----------------|
| **SAST** | Semgrep | Code vulnerabilities, anti-patterns |
| **Secrets** | Gitleaks | API keys, tokens, passwords in code |
| **Dependencies** | Trivy | Known CVEs in dependencies |
| **Container** | Trivy + Hadolint | Image vulnerabilities, Dockerfile issues |
| **DAST** | OWASP ZAP | Runtime vulnerabilities in running app |
| **Signing** | Cosign | Image signing, attestation, provenance |
| **SBOM** | Syft | Software Bill of Materials (CycloneDX) |

## Quick Start

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/full-pipeline.yml'
```

### GitHub Actions

Copy `templates/github/securepipe.yml` into `.github/workflows/`.

### Jenkins

```groovy
@Library('securepipe') _
securePipeFullScan()
```

### Standalone CLI

```bash
# Run all checks on current project
./securepipe.sh scan --all

# Run specific stage
./securepipe.sh scan --sast
./securepipe.sh scan --secrets
./securepipe.sh scan --container myimage:latest

# Generate HTML report
./securepipe.sh scan --all --report html

# Verbose mode (debug output)
./securepipe.sh scan --all --verbose
```

## Project Structure

```
SecurePipe/
├── .github/workflows/    # Self-testing CI pipeline
├── templates/
│   ├── github/           # GitHub Actions workflow
│   │   └── securepipe.yml
│   ├── gitlab/           # GitLab CI templates
│   │   ├── full-pipeline.yml
│   │   ├── sast.yml
│   │   ├── container-scanning.yml
│   │   ├── dependency-check.yml
│   │   ├── secrets.yml
│   │   ├── dast.yml
│   │   └── signing.yml
│   └── jenkins/          # Jenkins shared library
│       └── vars/
│           └── securePipeFullScan.groovy
├── scripts/
│   └── report-generator.py   # HTML/JSON report aggregation
├── tests/
│   └── test_securepipe.sh    # Test suite
├── docs/
│   ├── configuration.md
│   ├── customization.md
│   └── false-positives.md
├── examples/
│   └── vulnerable-app/   # Intentionally vulnerable demo app
└── securepipe.sh         # CLI entry point
```

## Configuration

Create `.securepipe.yml` in your project root:

```yaml
version: "1.0"

settings:
  fail_on_critical: true
  fail_on_high: true
  report_format: html
  output_dir: securepipe-reports/

sast:
  enabled: true
  tools: [semgrep]
  languages: [python, javascript, go]
  custom_rules: auto

secrets:
  enabled: true
  tools: [gitleaks]

dependencies:
  enabled: true
  tools: [trivy]
  ignore_cves: []

container:
  enabled: true
  tools: [trivy, hadolint]
  image: ""
  severity_threshold: ""

dast:
  enabled: true
  tools: [zap]
  target_url: "http://localhost:8080"

signing:
  enabled: true
  tools: [cosign]

sbom:
  enabled: true
  format: cyclonedx
```

## Features

- **Config-driven** — `.securepipe.yml` controls stages, thresholds, and tools
- **Fail-fast mode** — break the pipeline on critical/high findings
- **Severity-based gates** — `fail_on_critical` and `fail_on_high` per stage
- **HTML/JSON reports** — security reports with severity breakdown
- **CVE whitelisting** — ignore known false positives via config
- **Custom Semgrep rules** — pass custom rulesets through config or CLI
- **Multi-CI** — GitLab CI, Jenkins, GitHub Actions
- **Input validation** — image names and URLs are sanitized
- **Resource limits** — all Docker scanners run with memory/CPU/PID limits
- **Pinned images** — all scanner images use specific versions, not `:latest`
- **Pre-commit hooks** — Gitleaks + Hadolint available via `.pre-commit-config.yaml`

## Requirements

- Docker (for containerized scanners)
- jq (for result parsing)
- Git (for secrets detection)
- Optional: yq (for config parsing — falls back to python3 + PyYAML)

## Testing

```bash
bash tests/test_securepipe.sh
```

## Use Cases

- **Freelance DevSecOps** — Drop this into any client's CI/CD
- **Security audits** — Run standalone scans, deliver professional reports
- **Team onboarding** — Consistent security checks across all projects

## License

MIT License — use it, sell it, deploy it.

---

Built by [Mounik](https://github.com/Mounik)