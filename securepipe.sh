#!/usr/bin/env bash
#
# SecurePipe CLI — DevSecOps pipeline runner
# Usage: ./securepipe.sh scan --all [--report html|json] [--output dir]
#
set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SECUREPIPE_CONFIG:-.securepipe.yml}"
REPORT_DIR="${SECUREPIPE_OUTPUT:-securepipe-reports}"
REPORT_FORMAT="html"
FAIL_ON_CRITICAL=true
FAIL_ON_HIGH=true
EXIT_CODE=0
VERBOSE=false

SEMGREP_IMAGE="returntocorp/semgrep:1.64"
GITLEAKS_IMAGE="zricethezav/gitleaks:8.18"
TRIVY_IMAGE="aquasec/trivy:0.51"
HADOLINT_IMAGE="hadolint/hadolint:2.12-alpine"
ZAP_IMAGE="owasp/zap2docker-stable:2.15"
COSIGN_IMAGE="bitnami/cosign:2.4"
SYFT_IMAGE="anchore/syft:1.11"

CFG_SAST_ENABLED=true
CFG_SECRETS_ENABLED=true
CFG_DEPS_ENABLED=true
CFG_CONTAINER_ENABLED=true
CFG_DAST_ENABLED=true
CFG_SIGNING_ENABLED=true
CFG_SBOM_ENABLED=true
CFG_DAST_URL="http://localhost:8080"
CFG_CONTAINER_IMAGE=""
CFG_SEMGREP_CONFIG="auto"
CFG_IGNORE_CVES=""
CFG_SEVERITY_THRESHOLD=""

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
    echo -e "${BLUE}"
    echo "  ███████╗██████╗ ███████╗███████╗ ██████╗██╗██╗"
    echo "  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║██║"
    echo "  ███████╗██████╔╝█████╗  █████╗  ██║     ██║██║"
    echo "  ╚════██║██╔═══╝ ██╔══╝  ██╔══╝  ██║     ██║██║"
    echo "  ███████║██║     ███████╗███████╗╚██████╗██║██║"
    echo "  ╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝╚═╝╚═╝"
    echo -e "  DevSecOps Pipeline v${VERSION}${NC}"
    echo ""
}

log_info()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_stage() { echo -e "${BLUE}━━━ $1 ━━━${NC}"; }
log_debug() { [[ "$VERBOSE" == true ]] && echo -e "[…] $1" || true; }

parse_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_debug "Config file ${CONFIG_FILE} not found, using defaults"
        return
    fi

    log_debug "Loading config from ${CONFIG_FILE}"

    if ! command -v yq &>/dev/null; then
        log_debug "yq not found, using python3 fallback for config parsing"
        _parse_config_python
    else
        _parse_config_yq
    fi

    _apply_env_overrides
}

_parse_config_yq() {
    local cfg="$CONFIG_FILE"

    CFG_SAST_ENABLED=$(yq ".sast.enabled // true" "$cfg")
    CFG_SECRETS_ENABLED=$(yq ".secrets.enabled // true" "$cfg")
    CFG_DEPS_ENABLED=$(yq ".dependencies.enabled // true" "$cfg")
    CFG_CONTAINER_ENABLED=$(yq ".container.enabled // true" "$cfg")
    CFG_DAST_ENABLED=$(yq ".dast.enabled // true" "$cfg")
    CFG_SIGNING_ENABLED=$(yq ".signing.enabled // true" "$cfg")
    CFG_SBOM_ENABLED=$(yq ".sbom.enabled // true" "$cfg")

    FAIL_ON_CRITICAL=$(yq ".settings.fail_on_critical // true" "$cfg")
    FAIL_ON_HIGH=$(yq ".settings.fail_on_high // true" "$cfg")
    REPORT_FORMAT=$(yq ".settings.report_format // \"html\"" "$cfg")
    local cfg_output_dir
    cfg_output_dir=$(yq ".settings.output_dir // \"securepipe-reports/\"" "$cfg")
    [[ "$cfg_output_dir" != "null" && -n "$cfg_output_dir" ]] && REPORT_DIR="${cfg_output_dir%/}"

    CFG_DAST_URL=$(yq ".dast.target_url // \"http://localhost:8080\"" "$cfg")
    CFG_CONTAINER_IMAGE=$(yq ".container.image // \"\"" "$cfg")
    CFG_SEMGREP_CONFIG=$(yq ".sast.custom_rules // \"auto\"" "$cfg")
    CFG_SEVERITY_THRESHOLD=$(yq ".container.severity_threshold // \"\"" "$cfg")

    CFG_IGNORE_CVES=$(yq ".dependencies.ignore_cves[]?" "$cfg | tr '\n' ',' | sed 's/,$//")
}

_parse_config_python() {
    local cfg="$CONFIG_FILE"
    local py_script
    py_script=$(cat <<'PYEOF'
import yaml, sys, json
with open(sys.argv[1]) as f:
    c = yaml.safe_load(f) or {}
s = c.get("settings", {})
stages = ["sast", "secrets", "dependencies", "container", "dast", "signing", "sbom"]
out = {}
out["fail_on_critical"] = str(s.get("fail_on_critical", True)).lower()
out["fail_on_high"] = str(s.get("fail_on_high", True)).lower()
out["report_format"] = s.get("report_format", "html")
out["output_dir"] = s.get("output_dir", "securepipe-reports").rstrip("/")
for stage in stages:
    key = stage if stage != "dependencies" else "dependencies"
    out[f"{stage}_enabled"] = str(c.get(key, {}).get("enabled", True)).lower()
out["dast_url"] = c.get("dast", {}).get("target_url", "http://localhost:8080")
out["container_image"] = c.get("container", {}).get("image", "")
cr = c.get("sast", {}).get("custom_rules", [])
out["semgrep_config"] = ",".join(cr) if isinstance(cr, list) and cr else "auto"
out["severity_threshold"] = c.get("container", {}).get("severity_threshold", "")
ignore = c.get("dependencies", {}).get("ignore_cves", [])
out["ignore_cves"] = ",".join(ignore) if isinstance(ignore, list) and ignore else ""
json.dump(out, sys.stdout)
PYEOF
)
    eval "$(python3 -c "$py_script" "$cfg" 2>/dev/null | while IFS='=' read -r key val; do
        case "$key" in
            fail_on_critical) echo "FAIL_ON_CRITICAL=${val}" ;;
            fail_on_high) echo "FAIL_ON_HIGH=${val}" ;;
            report_format) echo "REPORT_FORMAT=${val}" ;;
            output_dir) echo "REPORT_DIR=${val}" ;;
            sast_enabled) echo "CFG_SAST_ENABLED=${val}" ;;
            secrets_enabled) echo "CFG_SECRETS_ENABLED=${val}" ;;
            dependencies_enabled) echo "CFG_DEPS_ENABLED=${val}" ;;
            container_enabled) echo "CFG_CONTAINER_ENABLED=${val}" ;;
            dast_enabled) echo "CFG_DAST_ENABLED=${val}" ;;
            signing_enabled) echo "CFG_SIGNING_ENABLED=${val}" ;;
            sbom_enabled) echo "CFG_SBOM_ENABLED=${val}" ;;
            dast_url) echo "CFG_DAST_URL=${val}" ;;
            container_image) echo "CFG_CONTAINER_IMAGE=${val}" ;;
            semgrep_config) echo "CFG_SEMGREP_CONFIG=${val}" ;;
            severity_threshold) echo "CFG_SEVERITY_THRESHOLD=${val}" ;;
            ignore_cves) echo "CFG_IGNORE_CVES=${val}" ;;
        esac
    done)"
}

_apply_env_overrides() {
    [[ "${SECUREPIPE_FAIL_ON_CRITICAL:-}" ]] && FAIL_ON_CRITICAL="$SECUREPIPE_FAIL_ON_CRITICAL"
    [[ "${SECUREPIPE_FAIL_ON_HIGH:-}" ]] && FAIL_ON_HIGH="$SECUREPIPE_FAIL_ON_HIGH"
    [[ "${SECUREPIPE_SKIP_SECRETS:-}" == "true" ]] && CFG_SECRETS_ENABLED=false
    [[ "${SECUREPIPE_SKIP_SAST:-}" == "true" ]] && CFG_SAST_ENABLED=false
    [[ "${SECUREPIPE_SKIP_DEPS:-}" == "true" ]] && CFG_DEPS_ENABLED=false
    [[ "${SECUREPIPE_SKIP_CONTAINER:-}" == "true" ]] && CFG_CONTAINER_ENABLED=false
    [[ "${SECUREPIPE_SKIP_DAST:-}" == "true" ]] && CFG_DAST_ENABLED=false
    [[ "${SECUREPIPE_SKIP_SIGNING:-}" == "true" ]] && CFG_SIGNING_ENABLED=false
    [[ "${SECUREPIPE_SKIP_SBOM:-}" == "true" ]] && CFG_SBOM_ENABLED=false
    [[ "${SECUREPIPE_CONTAINER_IMAGE:-}" ]] && CFG_CONTAINER_IMAGE="$SECUREPIPE_CONTAINER_IMAGE"
    [[ "${SECUREPIPE_DAST_URL:-}" ]] && CFG_DAST_URL="$SECUREPIPE_DAST_URL"
}

ensure_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker is required. Install it first."
        exit 1
    fi
}

ensure_jq() {
    if ! command -v jq &>/dev/null; then
        log_error "jq is required for result parsing. Install it first (apt install jq / brew install jq)."
        exit 1
    fi
}

validate_image_name() {
    local img="$1"
    if [[ ! "$img" =~ ^[a-zA-Z0-9._:/@-]+$ ]]; then
        log_error "Invalid container image name: ${img}"
        return 1
    fi
}

validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9._:/-]+$ ]]; then
        log_error "Invalid URL: ${url}"
        return 1
    fi
}

count_severity() {
    local results_file="$1"
    local severity="$2"
    if [[ -f "$results_file" ]]; then
        jq -r --arg sev "$severity" '
            if .results then
                [.results[] | select((.extra.severity // "INFO") | ascii_downcase == ($sev | ascii_downcase))] | length
            elif .Results then
                [.Results[]?.Vulnerabilities[]? | select((.Severity // "UNKNOWN") | ascii_downcase == ($sev | ascii_downcase))] | length
            else
                0
            end
        ' "$results_file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

check_severity_threshold() {
    local results_file="$1"
    local stage_name="$2"

    local crit_count high_count
    crit_count=$(jq -r '
        if .Results then
            [.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length
        elif .results then
            [.results[] | select((.extra.severity // "") | ascii_downcase == "critical")] | length
        else 0 end
    ' "$results_file" 2>/dev/null || echo "0")
    high_count=$(jq -r '
        if .Results then
            [.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length
        elif .results then
            [.results[] | select((.extra.severity // "") | ascii_downcase == "high")] | length
        else 0 end
    ' "$results_file" 2>/dev/null || echo "0")

    if [[ "$FAIL_ON_CRITICAL" == true && "$crit_count" -gt 0 ]]; then
        log_error "${stage_name}: ${crit_count} CRITICAL findings — pipeline will fail"
        EXIT_CODE=1
    fi
    if [[ "$FAIL_ON_HIGH" == true && "$high_count" -gt 0 ]]; then
        log_error "${stage_name}: ${high_count} HIGH findings — pipeline will fail"
        EXIT_CODE=1
    fi
}

run_scanner() {
    local description="$1"
    shift
    local cmd=("$@")

    log_debug "Running: ${cmd[*]}"
    if ! "${cmd[@]}"; then
        local rc=$?
        if [[ $rc -eq 1 ]]; then
            log_warn "${description}: scanner reported findings (exit ${rc})"
        else
            log_error "${description}: scanner failed with exit code ${rc}"
        fi
        return $rc
    fi
    return 0
}

# ─── SAST ────────────────────────────────────────────────────────────────
run_sast() {
    log_stage "SAST — Static Application Security Testing"
    local results_file="${REPORT_DIR}/sast-results.json"

    log_info "Running Semgrep (config: ${CFG_SEMGREP_CONFIG})..."
    local semgrep_config_arg="--config ${CFG_SEMGREP_CONFIG}"
    docker run --rm \
        --memory 2g --cpus 1 --pids-limit 100 \
        -v "$(pwd):/src:ro" \
        "${SEMGREP_IMAGE}" \
        semgrep ${semgrep_config_arg} --json --output "/src/${results_file}" /src || true

    if [[ -f "${results_file}" ]]; then
        local count
        count=$(jq '.results | length' "$results_file" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_warn "Semgrep found ${count} findings"
            check_severity_threshold "$results_file" "SAST"
        else
            log_info "Semgrep: no findings"
        fi
    else
        log_warn "Semgrep: no results file produced"
    fi
}

# ─── SECRETS ─────────────────────────────────────────────────────────────
run_secrets() {
    log_stage "Secrets Detection"
    local results_file="${REPORT_DIR}/secrets-results.json"

    log_info "Running Gitleaks..."
    docker run --rm \
        --memory 1g --cpus 1 --pids-limit 50 \
        -v "$(pwd):/repo:ro" \
        -v "$(pwd)/${REPORT_DIR}:/output" \
        "${GITLEAKS_IMAGE}" \
        detect --source /repo --report-format json --report-path /output/secrets-results.json || true

    if [[ -f "${results_file}" ]]; then
        local count
        count=$(jq 'length' "$results_file" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_error "Gitleaks found ${count} secrets! Check ${results_file}"
            EXIT_CODE=1
        else
            log_info "Gitleaks: no secrets found"
        fi
    else
        log_warn "Gitleaks: no results file produced"
    fi
}

# ─── DEPENDENCIES ────────────────────────────────────────────────────────
run_dependencies() {
    log_stage "Dependency Scanning"
    local results_file="${REPORT_DIR}/dependency-results.json"

    local trivy_severity_arg=""
    if [[ -n "$CFG_SEVERITY_THRESHOLD" ]]; then
        trivy_severity_arg="--severity ${CFG_SEVERITY_THRESHOLD}"
    fi

    local trivy_ignore_args=""
    if [[ -n "$CFG_IGNORE_CVES" ]]; then
        trivy_ignore_args="--ignorefile ${(s:,:)CFG_IGNORE_CVES}"
    fi

    log_info "Running Trivy filesystem scan..."
    docker run --rm \
        --memory 2g --cpus 1 --pids-limit 100 \
        -v "$(pwd):/repo:ro" \
        -v "$(pwd)/${REPORT_DIR}:/output" \
        "${TRIVY_IMAGE}" \
        fs --format json --output /output/dependency-results.json /repo ${trivy_severity_arg} ${trivy_ignore_args} || true

    if [[ -f "${results_file}" ]]; then
        local count
        count=$(jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' "$results_file" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_warn "Trivy found ${count} dependency vulnerabilities"
            check_severity_threshold "$results_file" "Dependencies"
        else
            log_info "Trivy: no dependency vulnerabilities"
        fi
    else
        log_warn "Trivy: no results file produced"
    fi
}

# ─── CONTAINER ───────────────────────────────────────────────────────────
run_container() {
    local image="${1:-}"
    if [[ -z "$image" ]]; then
        log_warn "No container image specified. Skipping container scan."
        return
    fi

    validate_image_name "$image" || return 1

    log_stage "Container Scanning — ${image}"
    local results_file="${REPORT_DIR}/container-results.json"

    log_info "Running Trivy image scan..."
    docker run --rm \
        --memory 2g --cpus 1 --pids-limit 100 \
        -v "$(pwd)/${REPORT_DIR}:/output" \
        "${TRIVY_IMAGE}" \
        image --format json --output /output/container-results.json "$image" || true

    if [[ -f "${results_file}" ]]; then
        local count
        count=$(jq '[.Results[]?.Vulnerabilities // [] | length] | add // 0' "$results_file" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_warn "Trivy found ${count} container vulnerabilities"
            check_severity_threshold "$results_file" "Container"
        else
            log_info "Trivy container: no vulnerabilities"
        fi
    else
        log_warn "Trivy image scan: no results file produced"
    fi

    if [[ -f "Dockerfile" ]]; then
        log_info "Running Hadolint on Dockerfile..."
        docker run --rm \
            --memory 512m --cpus 0.5 --pids-limit 20 \
            -i \
            "${HADOLINT_IMAGE}" \
            < Dockerfile || true
    fi

    log_info "Container scan complete"
}

# ─── DAST ────────────────────────────────────────────────────────────────
run_dast() {
    local target_url="${1:-${CFG_DAST_URL}}"
    validate_url "$target_url" || return 1

    log_stage "DAST — Dynamic Application Security Testing"
    local results_file="${REPORT_DIR}/dast-results.json"

    log_info "Running OWASP ZAP baseline scan against ${target_url}..."
    docker run --rm \
        --memory 2g --cpus 1 --pids-limit 100 \
        -v "$(pwd)/${REPORT_DIR}:/output" \
        "${ZAP_IMAGE}" \
        zap-baseline.py -t "$target_url" -J dast-results.json -r /output/dast-results.html || true

    cp "$(pwd)/${REPORT_DIR}/dast-results.json" "${results_file}" 2>/dev/null || true

    if [[ -f "${results_file}" ]]; then
        log_warn "DAST: findings reported — check ${results_file}"
        check_severity_threshold "$results_file" "DAST"
    else
        log_warn "DAST: ZAP report not found at expected path"
    fi
}

# ─── SIGNING ─────────────────────────────────────────────────────────────
run_signing() {
    local image="${1:-}"
    if [[ -z "$image" ]]; then
        log_warn "No container image specified. Skipping signing."
        return
    fi

    validate_image_name "$image" || return 1

    log_stage "Container Signing & Attestation"

    if [[ -z "${COSIGN_KEY:-}" ]]; then
        log_warn "COSIGN_KEY environment variable not set. Skipping signing."
        return
    fi

    log_info "Signing image with Cosign..."
    docker run --rm \
        --memory 512m --cpus 0.5 --pids-limit 20 \
        -e COSIGN_KEY \
        "${COSIGN_IMAGE}" \
        sign --key env://COSIGN_KEY "$image" || log_warn "Cosign signing failed"
}

# ─── SBOM ────────────────────────────────────────────────────────────────
run_sbom() {
    local image="${1:-}"
    log_stage "SBOM Generation"
    local results_file="${REPORT_DIR}/sbom-cyclonedx.json"

    log_info "Generating SBOM with Syft..."
    if [[ -n "$image" ]]; then
        docker run --rm \
            --memory 2g --cpus 1 --pids-limit 100 \
            -v "$(pwd)/${REPORT_DIR}:/output" \
            "${SYFT_IMAGE}" \
            "$image" -o cyclonedx-json > "${results_file}" || true
    else
        docker run --rm \
            --memory 2g --cpus 1 --pids-limit 100 \
            -v "$(pwd):/src:ro" \
            -v "$(pwd)/${REPORT_DIR}:/output" \
            "${SYFT_IMAGE}" \
            dir:/src -o cyclonedx-json > "${results_file}" || true
    fi

    if [[ -f "${results_file}" && -s "${results_file}" ]]; then
        log_info "SBOM generated: ${results_file}"
    else
        log_warn "SBOM generation failed or empty"
    fi
}

# ─── REPORT ──────────────────────────────────────────────────────────────
generate_report() {
    log_stage "Generating Report"

    if [[ "$REPORT_FORMAT" == "json" ]]; then
        local json_report="${REPORT_DIR}/securepipe-report.json"
        python3 -c "
import json, os, sys
report_dir = sys.argv[1]
output = {'stages': {}}
for f in os.listdir(report_dir):
    if f.endswith('-results.json'):
        with open(os.path.join(report_dir, f)) as fh:
            try:
                output['stages'][f.replace('-results.json','')] = json.load(fh)
            except: pass
with open(sys.argv[2], 'w') as fh:
    json.dump(output, fh, indent=2)
print(f'JSON report: {sys.argv[2]}')
" "$REPORT_DIR" "$json_report" || log_warn "JSON report generation failed"
        return
    fi

    local report_file="${REPORT_DIR}/securepipe-report.html"
    python3 "${SCRIPT_DIR}/scripts/report-generator.py" "${REPORT_DIR}" "${report_file}" || {
        echo "SecurePipe Scan Report — $(date)" > "${REPORT_DIR}/securepipe-report.txt"
        echo "========================================" >> "${REPORT_DIR}/securepipe-report.txt"
        for f in "${REPORT_DIR}"/*.json; do
            [[ -f "$f" ]] && echo "- $(basename "$f"): $(wc -c < "$f") bytes" >> "${REPORT_DIR}/securepipe-report.txt"
        done
        log_info "Text report: ${REPORT_DIR}/securepipe-report.txt"
        return
    }

    log_info "HTML report: ${report_file}"
}

# ─── MAIN ────────────────────────────────────────────────────────────────
main() {
    banner
    ensure_docker
    ensure_jq

    local run_sast_flag=false
    local run_secrets_flag=false
    local run_deps_flag=false
    local run_container_flag=false
    local run_dast_flag=false
    local run_signing_flag=false
    local run_sbom_flag=false
    local run_all=false
    local container_image=""
    local dast_url=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all)         run_all=true ;;
            --sast)        run_sast_flag=true ;;
            --secrets)     run_secrets_flag=true ;;
            --deps)        run_deps_flag=true ;;
            --container)   run_container_flag=true; shift; container_image="$1" ;;
            --dast)        run_dast_flag=true; shift; dast_url="$1" ;;
            --signing)     run_signing_flag=true; shift; container_image="$1" ;;
            --sbom)        run_sbom_flag=true ;;
            --report)      shift; REPORT_FORMAT="$1" ;;
            --output)      shift; REPORT_DIR="$1" ;;
            --config)      shift; CONFIG_FILE="$1" ;;
            --verbose|-v)  VERBOSE=true ;;
            -h|--help)
                echo "Usage: securepipe.sh scan [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --all          Run all stages"
                echo "  --sast         Static analysis"
                echo "  --secrets      Secrets detection"
                echo "  --deps         Dependency scanning"
                echo "  --container IMG  Container scanning"
                echo "  --dast URL     Dynamic testing"
                echo "  --signing IMG  Sign container image"
                echo "  --sbom         Generate SBOM"
                echo "  --report FMT   Report format (html|json)"
                echo "  --output DIR   Output directory"
                echo "  --config FILE  Config file path"
                echo "  --verbose      Show debug output"
                exit 0
                ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
        shift
    done

    parse_config
    mkdir -p "${REPORT_DIR}"

    if [[ "$run_all" == true ]]; then
        run_sast_flag=true
        run_secrets_flag=true
        run_deps_flag=true
        run_container_flag=true
        run_dast_flag=true
        run_signing_flag=true
        run_sbom_flag=true
    fi

    [[ -z "$container_image" ]] && [[ -n "$CFG_CONTAINER_IMAGE" ]] && container_image="$CFG_CONTAINER_IMAGE"
    [[ -z "$dast_url" ]] && dast_url="$CFG_DAST_URL"

    if [[ "$run_sast_flag" == false && "$run_secrets_flag" == false && "$run_deps_flag" == false \
          && "$run_container_flag" == false && "$run_dast_flag" == false && "$run_signing_flag" == false \
          && "$run_sbom_flag" == false ]]; then
        run_sast_flag=$CFG_SAST_ENABLED
        run_secrets_flag=$CFG_SECRETS_ENABLED
        run_deps_flag=$CFG_DEPS_ENABLED
        run_container_flag=$CFG_CONTAINER_ENABLED
        run_dast_flag=$CFG_DAST_ENABLED
        run_signing_flag=$CFG_SIGNING_ENABLED
        run_sbom_flag=$CFG_SBOM_ENABLED
    fi

    echo -e "${BLUE}Config:${NC} ${CONFIG_FILE}"
    echo -e "${BLUE}Output:${NC} ${REPORT_DIR}/"
    echo -e "${BLUE}Fail on critical:${NC} ${FAIL_ON_CRITICAL}"
    echo -e "${BLUE}Fail on high:${NC} ${FAIL_ON_HIGH}"
    echo ""

    [[ "$run_secrets_flag" == true ]] && run_secrets
    [[ "$run_sast_flag" == true ]]    && run_sast
    [[ "$run_deps_flag" == true ]]    && run_dependencies
    [[ "$run_container_flag" == true ]] && run_container "$container_image"
    [[ "$run_dast_flag" == true ]]    && run_dast "$dast_url"
    [[ "$run_signing_flag" == true ]] && run_signing "$container_image"
    [[ "$run_sbom_flag" == true ]]    && run_sbom "$container_image"

    generate_report

    echo ""
    if [[ $EXIT_CODE -eq 0 ]]; then
        log_info "All scans completed successfully"
    else
        log_error "Scans completed with findings that require attention"
    fi

    exit $EXIT_CODE
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi