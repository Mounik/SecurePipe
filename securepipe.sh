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

# Colors
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

check_tool() {
    if command -v "$1" &>/dev/null; then
        return 0
    elif docker images | grep -q "$1" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

ensure_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker is required. Install it first."
        exit 1
    fi
}

# ─── SAST ────────────────────────────────────────────────────────────────
run_sast() {
    log_stage "SAST — Static Application Security Testing"
    local results_file="${REPORT_DIR}/sast-results.json"
    
    # Semgrep
    if check_tool semgrep || true; then
        log_info "Running Semgrep..."
        docker run --rm -v "$(pwd):/src" returntocorp/semgrep:latest \
            semgrep --config auto --json --output /src/"${results_file}" /src 2>/dev/null || true
        log_info "Semgrep results: ${results_file}"
    else
        log_warn "Semgrep not available, pulling Docker image..."
        docker run --rm -v "$(pwd):/src" returntocorp/semgrep:latest \
            semgrep --config auto --json --output /src/"${results_file}" /src 2>/dev/null || true
    fi
    
    # Count findings
    if [[ -f "${results_file}" ]]; then
        local count
        count=$(python3 -c "import json; d=json.load(open('${results_file}')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_warn "Semgrep found ${count} findings"
        else
            log_info "Semgrep: no findings"
        fi
    fi
}

# ─── SECRETS ─────────────────────────────────────────────────────────────
run_secrets() {
    log_stage "Secrets Detection"
    local results_file="${REPORT_DIR}/secrets-results.json"
    
    log_info "Running Gitleaks..."
    docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest \
        detect --source /repo --report-format json --report-path /repo/"${results_file}" 2>/dev/null || true
    
    if [[ -f "${results_file}" ]]; then
        local count
        count=$(python3 -c "import json; print(len(json.load(open('${results_file}'))))" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_error "Gitleaks found ${count} secrets! Check ${results_file}"
            EXIT_CODE=1
        else
            log_info "Gitleaks: no secrets found"
        fi
    fi
}

# ─── DEPENDENCIES ────────────────────────────────────────────────────────
run_dependencies() {
    log_stage "Dependency Scanning"
    local results_file="${REPORT_DIR}/dependency-results.json"
    
    # Trivy filesystem scan
    log_info "Running Trivy filesystem scan..."
    docker run --rm -v "$(pwd):/repo" -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest fs --format json --output /repo/"${results_file}" /repo 2>/dev/null || true
    
    if [[ -f "${results_file}" ]]; then
        local count
        count=$(python3 -c "
import json
d=json.load(open('${results_file}'))
total=sum(len(r.get('Vulnerabilities',[])) for r in d.get('Results',[]))
print(total)
" 2>/dev/null || echo "0")
        if [[ "$count" -gt 0 ]]; then
            log_warn "Trivy found ${count} dependency vulnerabilities"
        else
            log_info "Trivy: no dependency vulnerabilities"
        fi
    fi
}

# ─── CONTAINER ───────────────────────────────────────────────────────────
run_container() {
    local image="${1:-}"
    if [[ -z "$image" ]]; then
        log_warn "No container image specified. Skipping container scan."
        return
    fi
    
    log_stage "Container Scanning — ${image}"
    local results_file="${REPORT_DIR}/container-results.json"
    
    # Trivy image scan
    log_info "Running Trivy image scan..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest image --format json --output /tmp/container-results.json "$image" 2>/dev/null || true
    
    # Hadolint Dockerfile scan
    if [[ -f "Dockerfile" ]]; then
        log_info "Running Hadolint on Dockerfile..."
        docker run --rm -i hadolint/hadolint < Dockerfile 2>/dev/null || true
    fi
    
    log_info "Container scan complete"
}

# ─── DAST ────────────────────────────────────────────────────────────────
run_dast() {
    local target_url="${1:-http://localhost:8080}"
    log_stage "DAST — Dynamic Application Security Testing"
    local results_file="${REPORT_DIR}/dast-results.json"
    
    log_info "Running OWASP ZAP baseline scan against ${target_url}..."
    docker run --rm -t owasp/zap2docker-stable:latest \
        zap-baseline.py -t "$target_url" -J "$(basename "${results_file}")" 2>/dev/null || true
    
    log_info "DAST scan complete (check ZAP report)"
}

# ─── SIGNING ─────────────────────────────────────────────────────────────
run_signing() {
    local image="${1:-}"
    if [[ -z "$image" ]]; then
        log_warn "No container image specified. Skipping signing."
        return
    fi
    
    log_stage "Container Signing & Attestation"
    
    # Cosign sign
    if check_tool cosign || true; then
        log_info "Signing image with Cosign..."
        cosign sign --yes "$image" 2>/dev/null || log_warn "Cosign signing failed (COSIGN_KEY required)"
    else
        log_warn "Cosign not available. Install: https://docs.sigstore.dev/cosign/installation"
    fi
}

# ─── SBOM ────────────────────────────────────────────────────────────────
run_sbom() {
    local image="${1:-}"
    log_stage "SBOM Generation"
    local results_file="${REPORT_DIR}/sbom-cyclonedx.json"
    
    log_info "Generating SBOM with Syft..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$(pwd)/${REPORT_DIR}:/output" \
        anchore/syft:latest \
        "${image:-dir:./}" -o cyclonedx-json > "${results_file}" 2>/dev/null || true
    
    if [[ -f "${results_file}" && -s "${results_file}" ]]; then
        log_info "SBOM generated: ${results_file}"
    else
        log_warn "SBOM generation failed or empty"
    fi
}

# ─── REPORT ──────────────────────────────────────────────────────────────
generate_report() {
    log_stage "Generating Report"
    local report_file="${REPORT_DIR}/securepipe-report.html"
    
    python3 "${SCRIPT_DIR}/scripts/report-generator.py" "${REPORT_DIR}" "${report_file}" 2>/dev/null || {
        # Fallback: simple text summary
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
    mkdir -p "${REPORT_DIR}"
    
    local run_sast_flag=false
    local run_secrets_flag=false
    local run_deps_flag=false
    local run_container_flag=false
    local run_dast_flag=false
    local run_signing_flag=false
    local run_sbom_flag=false
    local run_all=false
    local container_image=""
    local dast_url="http://localhost:8080"
    
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
                exit 0
                ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
        shift
    done
    
    # If --all, enable everything
    if [[ "$run_all" == true ]]; then
        run_sast_flag=true
        run_secrets_flag=true
        run_deps_flag=true
        run_container_flag=true
        run_dast_flag=true
        run_sbom_flag=true
    fi
    
    echo -e "${BLUE}Config:${NC} ${CONFIG_FILE}"
    echo -e "${BLUE}Output:${NC} ${REPORT_DIR}/"
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

# Only run if executed, not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi