# SecurePipe 🔒

**Production-ready DevSecOps pipeline — drop-in security for any CI/CD**

SecurePipe is a complete, opinionated DevSecOps pipeline template that secures every stage of your software delivery. One configuration file, full security coverage.

## 🛡️ Security Stages

| Stage | Tool | What it detects |
|-------|------|-----------------|
| **SAST** | Semgrep + CodeQL | Code vulnerabilities, anti-patterns |
| **Secrets** | Gitleaks | API keys, tokens, passwords in code |
| **Dependencies** | OWASP Dep-Check + Trivy | Known CVEs in dependencies |
| **Container** | Trivy + Hadolint | Image vulnerabilities, Dockerfile issues |
| **DAST** | OWASP ZAP | Runtime vulnerabilities in running app |
| **Signing** | Cosign + Syft | Image signing, attestation, provenance |
| **SBOM** | Syft | Software Bill of Materials (SPDX/CycloneDX) |

## 🚀 Quick Start

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Mounik/SecurePipe/main/templates/gitlab/full-pipeline.yml'
```

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
```

## 📁 Project Structure

```
SecurePipe/
├── templates/
│   ├── gitlab/           # GitLab CI templates
│   │   ├── full-pipeline.yml
│   │   ├── sast.yml
│   │   ├── container-scanning.yml
│   │   ├── dependency-check.yml
│   │   ├── secrets-detection.yml
│   │   ├── dast.yml
│   │   └── signing.yml
│   └── jenkins/          # Jenkins shared library
│       └── vars/
│           └── securePipeFullScan.groovy
├── scripts/
│   ├── sast/             # SAST runner scripts
│   ├── container/        # Container scanning scripts
│   ├── dependency/        # Dependency check scripts
│   ├── secrets/          # Secrets detection scripts
│   ├── dast/             # DAST runner scripts
│   ├── signing/          # Signing & attestation scripts
│   └── sbom/             # SBOM generation scripts
├── reports/
│   └── templates/        # HTML/JSON report templates
├── docs/
│   ├── configuration.md
│   ├── customization.md
│   └── false-positives.md
├── examples/
│   └── vulnerable-app/   # Intentionally vulnerable demo app
└── securepipe.sh         # CLI entry point
```

## ⚙️ Configuration

Create `.securepipe.yml` in your project root:

```yaml
version: "1.0"

# Global settings
settings:
  fail_on_critical: true
  fail_on_high: true
  report_format: html
  output_dir: securepipe-reports/

# Stage configuration
sast:
  enabled: true
  tools: [semgrep, codeql]
  languages: [python, javascript, go]

secrets:
  enabled: true
  tools: [gitleaks]

dependencies:
  enabled: true
  tools: [trivy, owasp-depcheck]
  ignore_cves: []

container:
  enabled: true
  tools: [trivy, hadolint]
  image: "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"

dast:
  enabled: true
  tools: [zap]
  target_url: "http://localhost:8080"

signing:
  enabled: true
  tools: [cosign]
  registry: "${CI_REGISTRY}"

sbom:
  enabled: true
  format: cyclonedx
```

## 🎯 Features

- **Zero-config defaults** — works out of the box for most projects
- **Fail-fast mode** — break the pipeline on critical/high findings
- **HTML reports** — beautiful, shareable security reports
- **CVE whitelisting** — ignore known false positives via `.securepipe.yml`
- **Multi-language** — Python, JavaScript, Go, Java, Docker
- **Multi-CI** — GitLab CI, Jenkins, GitHub Actions (coming soon)
- **Offline mode** — air-gapped environments supported
- **Compliance mapping** — CIS, OWASP Top 10, NIST references

## 🔧 Requirements

- Docker (for containerized scanners)
- Git (for secrets detection)
- Optional: Semgrep, Trivy, Gitleaks (if running locally)

## 📊 Example Report

SecurePipe generates HTML reports with severity breakdown, CVE details, and remediation guidance.

## 🤝 Use Cases

- **Freelance DevSecOps** — Drop this into any client's CI/CD, charge for setup + maintenance
- **Security audits** — Run standalone scans, deliver professional reports
- **Compliance** — Map findings to CIS, OWASP, NIST frameworks
- **Team onboarding** — Consistent security checks across all projects

## 📄 License

MIT License — use it, sell it, deploy it.

---

Built by [Mounik](https://github.com/Mounik) — DevSecOps Engineer | [docker-stacks](https://github.com/Mounik/docker-stacks) | [devops-toolkit](https://github.com/Mounik/devops-toolkit)