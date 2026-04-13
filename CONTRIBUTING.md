# Contributing to SecurePipe

Thank you for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Mounik/SecurePipe.git
cd SecurePipe

# Run the test suite
bash tests/test_securepipe.sh

# Run SecurePipe locally
./securepipe.sh scan --all --verbose
```

## Making Changes

1. **Fork** the repository
2. Create a **feature branch** (`git checkout -b feature/my-change`)
3. Make your changes
4. **Run the tests** (`bash tests/test_securepipe.sh`)
5. **Commit** with clear messages
6. **Push** and open a Pull Request

## Code Style

- **Bash**: Follow `shellcheck` recommendations. Use `set -euo pipefail`
- **Python**: PEP 8, type hints where helpful
- **YAML**: 2-space indentation
- **No comments** in code unless they explain "why", not "what"

## Pull Request Guidelines

- One logical change per PR
- Include tests for new functionality
- Update documentation if behavior changes
- All CI checks must pass

## Reporting Issues

- Use GitHub Issues
- Include: OS, Docker version, SecurePipe version, reproduction steps
- For security issues, see [SECURITY.md](SECURITY.md)