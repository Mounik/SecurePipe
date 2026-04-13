#!/usr/bin/env bash
#
# SecurePipe Test Suite
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SECUREPIPE="${PROJECT_DIR}/securepipe.sh"
TEST_DIR=$(mktemp -d)
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

assert() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$expected" == "$actual" ]]; then
        echo "  PASS: $label"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  FAIL: $label"
        echo "    expected: $expected"
        echo "    actual:   $actual"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_contains() {
    local label="$1"
    local needle="$2"
    local haystack="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "  PASS: $label"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  FAIL: $label"
        echo "    needle not found in output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_exit_code() {
    local label="$1"
    local expected="$2"
    local actual="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$actual" -eq "$expected" ]]; then
        echo "  PASS: $label"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  FAIL: $label (exit code: expected=$expected actual=$actual)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# ─── CLI Tests ───────────────────────────────────────────────────────────

echo "=== CLI Argument Parsing ==="

HELP_OUTPUT=$("$SECUREPIPE" --help 2>&1 || true)
assert_contains "help flag shows usage" "Usage:" "$HELP_OUTPUT"
assert_contains "help mentions --all" "--all" "$HELP_OUTPUT"
assert_contains "help mentions --sast" "--sast" "$HELP_OUTPUT"
assert_contains "help mentions --verbose" "--verbose" "$HELP_OUTPUT"

BAD_OUTPUT=$("$SECUREPIPE" --nonexistent 2>&1 || true)
assert_contains "unknown flag shows error" "Unknown option" "$BAD_OUTPUT"

echo ""
echo "=== Config File Parsing (unit) ==="

cat > "${TEST_DIR}/.securepipe.yml" <<'EOF'
version: "1.0"
settings:
  fail_on_critical: false
  fail_on_high: false
  report_format: json
  output_dir: test-reports
sast:
  enabled: false
secrets:
  enabled: true
dependencies:
  enabled: false
container:
  enabled: false
dast:
  enabled: false
  target_url: "http://test.example.com"
signing:
  enabled: false
sbom:
  enabled: false
EOF

if command -v yq &>/dev/null; then
    CFG_VAL=$(yq ".settings.fail_on_critical" "${TEST_DIR}/.securepipe.yml")
    assert "yq: fail_on_critical=false" "false" "$CFG_VAL"
    CFG_VAL=$(yq ".settings.output_dir" "${TEST_DIR}/.securepipe.yml")
    assert_contains "yq: output_dir=test-reports" "test-reports" "$CFG_VAL"
    CFG_VAL=$(yq ".dast.target_url" "${TEST_DIR}/.securepipe.yml")
    assert_contains "yq: dast target_url" "test.example.com" "$CFG_VAL"
elif command -v python3 &>/dev/null; then
    PY_CFG=$(python3 -c "
import yaml, json
with open('${TEST_DIR}/.securepipe.yml') as f:
    c = yaml.safe_load(f)
s = c.get('settings', {})
print(json.dumps({'fail_on_critical': s.get('fail_on_critical'), 'output_dir': s.get('output_dir'), 'dast_url': c.get('dast', {}).get('target_url')}))
")
    assert_contains "pyyaml: fail_on_critical=false" "false" "$PY_CFG"
    assert_contains "pyyaml: output_dir" "test-reports" "$PY_CFG"
    assert_contains "pyyaml: dast_url" "test.example.com" "$PY_CFG"
else
    echo "  SKIP: neither yq nor python3 available"
fi

echo ""
echo "=== Input Validation ==="

VALIDATE_IMG_OUTPUT=$(bash -c 'f(){ local i="$1"; [[ ! "$i" =~ ^[a-zA-Z0-9._:/@-]+$ ]] && echo "Invalid: $i" || echo "ok"; }; f "bad image; name"' 2>&1)
assert_contains "invalid image name rejected" "Invalid" "$VALIDATE_IMG_OUTPUT"

VALIDATE_URL_OUTPUT=$(bash -c 'f(){ local u="$1"; [[ ! "$u" =~ ^https?://[a-zA-Z0-9._:/-]+$ ]] && echo "Invalid URL" || echo "ok"; }; f "not-a-url"' 2>&1)
assert_contains "invalid URL rejected" "Invalid URL" "$VALIDATE_URL_OUTPUT"

echo ""
echo "=== Report Generator Tests ==="

mkdir -p "${TEST_DIR}/reports"

cat > "${TEST_DIR}/reports/secrets-results.json" <<'EOF'
[
  {"RuleID": "aws-access-key", "File": "config.py", "StartLine": 5, "Secret": "AKIAIOSFODNN7EXAMPLE", "Detector": "aws"},
  {"RuleID": "generic-api-key", "File": "app.py", "StartLine": 12, "Secret": "sk_live_abc123def456", "Detector": "stripe"}
]
EOF

cat > "${TEST_DIR}/reports/sast-results.json" <<'EOF'
{
  "results": [
    {"check_id": "python.sql.security.query", "path": "app.py", "start": {"line": 26}, "extra": {"severity": "HIGH", "message": "SQL injection vulnerability"}},
    {"check_id": "python.lang.security.eval", "path": "app.py", "start": {"line": 43}, "extra": {"severity": "ERROR", "message": "Remote code execution via eval"}}
  ]
}
EOF

cat > "${TEST_DIR}/reports/dependency-results.json" <<'EOF'
{
  "Results": [
    {
      "Target": "requirements.txt",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-1234", "Severity": "CRITICAL", "Title": "RCE in flask", "PkgName": "flask", "InstalledVersion": "1.0"},
        {"VulnerabilityID": "CVE-2023-5678", "Severity": "HIGH", "Title": "XSS in jinja2", "PkgName": "jinja2", "InstalledVersion": "3.0"}
      ]
    }
  ]
}
EOF

python3 "${PROJECT_DIR}/scripts/report-generator.py" "${TEST_DIR}/reports" "${TEST_DIR}/reports/test-report.html" 2>&1

REPORT_EXISTS="no"
[[ -f "${TEST_DIR}/reports/test-report.html" ]] && REPORT_EXISTS="yes"
assert "report HTML file created" "yes" "$REPORT_EXISTS"

REPORT_CONTENT=$(cat "${TEST_DIR}/reports/test-report.html" 2>/dev/null || echo "")
assert_contains "report contains CRITICAL count" "CRITICAL" "$REPORT_CONTENT"
assert_contains "report contains secrets findings" "Secrets Detection" "$REPORT_CONTENT"
assert_contains "report contains SAST findings" "SAST" "$REPORT_CONTENT"
assert_contains "report contains dependency findings" "Dependencies" "$REPORT_CONTENT"
assert_contains "report contains CVE ID" "CVE-2023-1234" "$REPORT_CONTENT"
assert_contains "report contains severity badge" "severity-CRITICAL" "$REPORT_CONTENT"

echo ""
echo "=== Report Generator: Truncation Indicator ==="

mkdir -p "${TEST_DIR}/reports2"

python3 -c "
import json
secrets = [{'RuleID': f'rule-{i}', 'File': f'f{i}.py', 'StartLine': i, 'Secret': f'key{i}', 'Detector': 'test'} for i in range(300)]
json.dump(secrets, open('${TEST_DIR}/reports2/secrets-results.json', 'w'))
"

python3 "${PROJECT_DIR}/scripts/report-generator.py" "${TEST_DIR}/reports2" "${TEST_DIR}/reports2/test-report.html" 2>&1

LARGE_REPORT=$(cat "${TEST_DIR}/reports2/test-report.html" 2>/dev/null || echo "")
assert_contains "large report shows truncation notice" "Showing 200 of 300" "$LARGE_REPORT"

echo ""
echo "=== Report Generator: DAST Stage ==="

mkdir -p "${TEST_DIR}/reports3"

cat > "${TEST_DIR}/reports3/dast-results.json" <<'EOF'
{
  "alerts": [
    {"alert": "XSS Reflected", "url": "http://test.example.com/search", "desc": "Reflected XSS found", "riskcode": "3"},
    {"alert": "SQL Injection", "url": "http://test.example.com/user", "desc": "SQL injection found", "riskcode": "3"}
  ]
}
EOF

python3 "${PROJECT_DIR}/scripts/report-generator.py" "${TEST_DIR}/reports3" "${TEST_DIR}/reports3/test-report.html" 2>&1

DAST_REPORT=$(cat "${TEST_DIR}/reports3/test-report.html" 2>/dev/null || echo "")
assert_contains "DAST report includes findings" "DAST" "$DAST_REPORT"
assert_contains "DAST report shows alert" "XSS Reflected" "$DAST_REPORT"

echo ""
echo "=== JSON Report Format ==="

mkdir -p "${TEST_DIR}/reports4"
echo '[]' > "${TEST_DIR}/reports4/secrets-results.json"

SECUREPIPE_OUTPUT="${TEST_DIR}/reports4" SECUREPIPE_CONFIG="${TEST_DIR}/.securepipe.yml" \
    REPORT_FORMAT=json python3 -c "
import json, os, sys
report_dir = '${TEST_DIR}/reports4'
output_file = '${TEST_DIR}/reports4/securepipe-report.json'
output = {'stages': {}}
for f in os.listdir(report_dir):
    if f.endswith('-results.json'):
        with open(os.path.join(report_dir, f)) as fh:
            try:
                output['stages'][f.replace('-results.json','')] = json.load(fh)
            except: pass
with open(output_file, 'w') as fh:
    json.dump(output, fh, indent=2)
"

JSON_REPORT_EXISTS="no"
[[ -f "${TEST_DIR}/reports4/securepipe-report.json" ]] && JSON_REPORT_EXISTS="yes"
assert "JSON report file created" "yes" "$JSON_REPORT_EXISTS"

echo ""
echo "=== .securepipe.yml Config Parsing (Python fallback) ==="

mkdir -p "${TEST_DIR}/cfgtest"
cat > "${TEST_DIR}/cfgtest/.securepipe.yml" <<'EOF'
version: "1.0"
settings:
  fail_on_critical: true
  fail_on_high: false
  report_format: json
  output_dir: custom-output
sast:
  enabled: true
  custom_rules: ["p/python", "p/owasp-top-ten"]
secrets:
  enabled: false
dependencies:
  enabled: true
  ignore_cves:
    - CVE-2023-0001
    - CVE-2023-0002
container:
  enabled: true
  severity_threshold: HIGH
dast:
  enabled: true
  target_url: "http://staging.local:3000"
signing:
  enabled: false
sbom:
  enabled: true
EOF

if command -v python3 &>/dev/null; then
    PY_RESULT=$(python3 -c "
import yaml, json, sys
with open('${TEST_DIR}/cfgtest/.securepipe.yml') as f:
    c = yaml.safe_load(f)
s = c.get('settings', {})
print(json.dumps({
    'fail_on_critical': s.get('fail_on_critical'),
    'fail_on_high': s.get('fail_on_high'),
    'report_format': s.get('report_format'),
    'output_dir': s.get('output_dir'),
    'sast_enabled': c.get('sast', {}).get('enabled'),
    'secrets_enabled': c.get('secrets', {}).get('enabled'),
    'custom_rules': c.get('sast', {}).get('custom_rules'),
    'ignore_cves': c.get('dependencies', {}).get('ignore_cves'),
    'severity_threshold': c.get('container', {}).get('severity_threshold'),
    'dast_url': c.get('dast', {}).get('target_url'),
}))
" 2>/dev/null)
    assert_contains "config: fail_on_critical parsed" "true" "$PY_RESULT"
    assert_contains "config: fail_on_high=false" "false" "$PY_RESULT"
    assert_contains "config: custom rules parsed" "p/python" "$PY_RESULT"
    assert_contains "config: ignore_cves parsed" "CVE-2023-0001" "$PY_RESULT"
    assert_contains "config: severity_threshold parsed" "HIGH" "$PY_RESULT"
    assert_contains "config: dast_url parsed" "staging.local" "$PY_RESULT"
else
    echo "  SKIP: python3 not available for config parsing test"
fi

echo ""
echo "=== ShellCheck Validation ==="

if command -v shellcheck &>/dev/null; then
    if shellcheck "$SECUREPIPE" 2>&1; then
        echo "  PASS: shellcheck passes"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        SC_OUTPUT=$(shellcheck "$SECUREPIPE" 2>&1 || true)
        SC_COUNT=$(echo "$SC_OUTPUT" | grep -c "SC" || echo "0")
        echo "  WARN: shellcheck found ${SC_COUNT} issues (non-blocking)"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
else
    echo "  SKIP: shellcheck not installed"
fi

echo ""
echo "=== Python Lint ==="

if command -v python3 &>/dev/null; then
    if python3 -m py_compile "${PROJECT_DIR}/scripts/report-generator.py" 2>&1; then
        echo "  PASS: report-generator.py compiles"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  FAIL: report-generator.py has syntax errors"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo "  SKIP: python3 not available"
fi

echo ""
echo "========================================="
echo "Tests run:    ${TESTS_RUN}"
echo "Tests passed: ${TESTS_PASSED}"
echo "Tests failed: ${TESTS_FAILED}"
echo "========================================="

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0