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

## Custom Trivy Policies

Create Rego policies for custom checks:

```rego
# custom-policy.rego
package trivy

deny[msg] {
  input.resource.container.image.tag == "latest"
  msg := sprintf("Image uses :latest tag: %s", [input.resource.container.image.name])
}
```

Reference in config:
```yaml
container:
  trivy_policy: custom-policy.rego
```

## Custom Report Templates

Override the default HTML report by providing a Jinja2 template:

```yaml
settings:
  report_template: path/to/custom-template.html
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