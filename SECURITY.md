# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SecurePipe, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security findings to the maintainer privately
3. Include: description, steps to reproduce, affected versions, potential impact

## What qualifies as a security issue

- Vulnerabilities in SecurePipe's own code that could compromise build pipelines
- Improper handling of secrets or credentials within the tool
- Container escape vectors via SecurePipe's Docker usage
- Supply chain risks in SecurePipe's default image references

## What does NOT qualify

- Vulnerabilities detected by SecurePipe in your own code (that's the tool working correctly)
- Vulnerabilities in third-party scanner tools (report to the upstream project)
- Issues already flagged by SecurePipe itself

## Response timeline

- Acknowledgment within 48 hours
- Initial assessment within 5 business days
- Fix or mitigation within 30 days (severity-dependent)