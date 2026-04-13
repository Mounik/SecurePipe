#!/usr/bin/env python3
"""
SecurePipe Report Generator
Aggregates all scan results into a single HTML report.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

MAX_FINDINGS_PER_STAGE = 200

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecurePipe Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #58a6ff; font-size: 2rem; margin-bottom: 0.5rem; }}
  h2 {{ color: #8b949e; font-size: 1.1rem; font-weight: 400; margin-bottom: 2rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; }}
  .card-title {{ font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }}
  .card-value {{ font-size: 2rem; font-weight: 700; }}
  .card-value.critical {{ color: #f85149; }}
  .card-value.high {{ color: #d29922; }}
  .card-value.medium {{ color: #58a6ff; }}
  .card-value.low {{ color: #3fb950; }}
  .card-value.clean {{ color: #3fb950; }}
  .stage {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .stage-header {{ padding: 1rem 1.5rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; }}
  .stage-name {{ font-weight: 600; font-size: 1.1rem; }}
  .stage-badge {{ padding: 0.25rem 0.75rem; border-radius: 1rem; font-size: 0.8rem; font-weight: 600; }}
  .badge-pass {{ background: #1b4332; color: #3fb950; }}
  .badge-warn {{ background: #432a1b; color: #d29922; }}
  .badge-fail {{ background: #431b1b; color: #f85149; }}
  .stage-body {{ padding: 1rem 1.5rem; }}
  .finding {{ padding: 0.75rem 0; border-bottom: 1px solid #21262d; }}
  .finding:last-child {{ border-bottom: none; }}
  .finding-rule {{ font-weight: 600; margin-bottom: 0.25rem; }}
  .finding-file {{ color: #8b949e; font-size: 0.85rem; font-family: monospace; }}
  .finding-message {{ color: #c9d1d9; font-size: 0.9rem; margin-top: 0.25rem; }}
  .severity {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: 700; margin-right: 0.5rem; }}
  .severity-CRITICAL {{ background: #f8514920; color: #f85149; }}
  .severity-HIGH {{ background: #d2992220; color: #d29922; }}
  .severity-MEDIUM {{ background: #58a6ff20; color: #58a6ff; }}
  .severity-LOW {{ background: #3fb95020; color: #3fb950; }}
  .severity-INFO {{ background: #8b949e20; color: #8b949e; }}
  .timestamp {{ color: #484f58; font-size: 0.8rem; margin-bottom: 1rem; }}
  .no-findings {{ color: #3fb950; padding: 1rem 0; }}
  .truncated {{ color: #d29922; font-size: 0.85rem; padding: 0.5rem 0; font-style: italic; }}
  footer {{ text-align: center; color: #484f58; margin-top: 2rem; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>SecurePipe Report</h1>
  <h2>DevSecOps Pipeline Scan Results</h2>
  <p class="timestamp">Generated: {timestamp}</p>

  <div class="summary">
    {summary_cards}
  </div>

  {stages_html}

  <footer>
    SecurePipe v1.0.0
  </footer>
</div>
</html>"""


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def count_severity(vulns, severity):
    return sum(
        1 for v in vulns if v.get("Severity", v.get("severity", "")).upper() == severity
    )


def process_secrets(data):
    findings = []
    total = 0
    if isinstance(data, list):
        total = len(data)
        for item in data[:MAX_FINDINGS_PER_STAGE]:
            findings.append(
                {
                    "rule": item.get("RuleID", "Secret detected"),
                    "file": f"{item.get('File', '')}:{item.get('StartLine', '')}",
                    "message": f"Potential {item.get('Secret', '***')[:20]}... ({item.get('Detector', 'unknown')})",
                    "severity": "CRITICAL",
                }
            )
    return findings, total


def process_sast(data):
    findings = []
    total = 0
    results = data.get("results", []) if isinstance(data, dict) else []
    total = len(results)
    for r in results[:MAX_FINDINGS_PER_STAGE]:
        sev = r.get("extra", {}).get("severity", "INFO").upper()
        if sev == "ERROR":
            sev = "HIGH"
        findings.append(
            {
                "rule": r.get("check_id", "Unknown rule"),
                "file": f"{r.get('path', '')}:{r.get('start', {}).get('line', '')}",
                "message": r.get("extra", {}).get("message", ""),
                "severity": sev,
            }
        )
    return findings, total


def process_deps(data):
    findings = []
    total = 0
    results = data.get("Results", []) if isinstance(data, dict) else []
    for r in results:
        vulns = r.get("Vulnerabilities", [])
        total += len(vulns)
        for v in vulns[:MAX_FINDINGS_PER_STAGE]:
            findings.append(
                {
                    "rule": v.get("VulnerabilityID", "CVE"),
                    "file": r.get("Target", ""),
                    "message": f"{v.get('Title', '')} — {v.get('PrimaryPackage', v.get('PkgName', ''))} {v.get('InstalledVersion', '')}",
                    "severity": v.get("Severity", "UNKNOWN").upper(),
                }
            )
    if len(findings) > MAX_FINDINGS_PER_STAGE:
        findings = findings[:MAX_FINDINGS_PER_STAGE]
    return findings, total


def process_container(data):
    findings = []
    total = 0
    if isinstance(data, dict):
        for r in data.get("Results", []):
            vulns = r.get("Vulnerabilities", [])
            total += len(vulns)
            for v in vulns[:MAX_FINDINGS_PER_STAGE]:
                findings.append(
                    {
                        "rule": v.get("VulnerabilityID", ""),
                        "file": r.get("Target", ""),
                        "message": f"{v.get('Title', '')} — {v.get('PkgName', '')} {v.get('InstalledVersion', '')}",
                        "severity": v.get("Severity", "UNKNOWN").upper(),
                    }
                )
    if len(findings) > MAX_FINDINGS_PER_STAGE:
        findings = findings[:MAX_FINDINGS_PER_STAGE]
    return findings, total


def process_dast(data):
    findings = []
    total = 0
    if isinstance(data, dict):
        alerts = data.get("alerts") or data.get("site", [{}])
        if isinstance(alerts, list):
            total = len(alerts)
            for alert in alerts[:MAX_FINDINGS_PER_STAGE]:
                findings.append(
                    {
                        "rule": alert.get("alert", alert.get("name", "ZAP Finding")),
                        "file": alert.get("url", "N/A"),
                        "message": alert.get("desc", alert.get("description", "")),
                        "severity": alert.get(
                            "riskcode", alert.get("risk", "INFO")
                        ).upper(),
                    }
                )
    return findings, total


STAGES = [
    ("secrets", "Secrets Detection", "secrets-results.json", process_secrets),
    ("sast", "SAST", "sast-results.json", process_sast),
    ("deps", "Dependencies", "dependency-results.json", process_deps),
    ("container", "Container", "container-results.json", process_container),
    ("dast", "DAST", "dast-results.json", process_dast),
]


def main():
    report_dir = sys.argv[1] if len(sys.argv) > 1 else "securepipe-reports"
    output_file = (
        sys.argv[2] if len(sys.argv) > 2 else f"{report_dir}/securepipe-report.html"
    )

    all_findings = {}
    all_totals = {}
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for key, name, filename, processor in STAGES:
        data = load_json(os.path.join(report_dir, filename))
        if data:
            findings, total = processor(data)
        else:
            findings, total = [], 0
        all_findings[key] = findings
        all_totals[key] = total
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in totals:
                totals[sev] += 1

    summary_cards = ""
    card_defs = [
        ("CRITICAL", totals["CRITICAL"]),
        ("HIGH", totals["HIGH"]),
        ("MEDIUM", totals["MEDIUM"]),
        ("LOW", totals["LOW"]),
        ("INFO", totals["INFO"]),
    ]
    for label, count in card_defs:
        cls = "clean" if count == 0 else label.lower()
        summary_cards += f'<div class="card"><div class="card-title">{label}</div><div class="card-value {cls}">{count}</div></div>\n'

    stages_html = ""
    for key, name, filename, _ in STAGES:
        findings = all_findings.get(key, [])
        total = all_totals.get(key, 0)
        if not findings:
            badge_cls = "pass"
            badge_text = "PASSED"
        elif any(f["severity"] == "CRITICAL" for f in findings):
            badge_cls = "fail"
            badge_text = f"{len(findings)} CRITICAL"
        else:
            badge_cls = "warn"
            badge_text = f"{len(findings)} findings"

        body = ""
        if not findings:
            body = '<div class="no-findings">No findings</div>'
        else:
            for f in findings:
                body += f"""<div class="finding">
                    <div class="finding-rule"><span class="severity severity-{f["severity"]}">{f["severity"]}</span>{f["rule"]}</div>
                    <div class="finding-file">{f["file"]}</div>
                    <div class="finding-message">{f["message"]}</div>
                </div>\n"""
            if total > len(findings):
                body += f'<div class="truncated">Showing {len(findings)} of {total} findings — see raw JSON for complete results</div>\n'

        stages_html += f"""<div class="stage">
            <div class="stage-header">
                <span class="stage-name">{name}</span>
                <span class="stage-badge badge-{badge_cls}">{badge_text}</span>
            </div>
            <div class="stage-body">{body}</div>
        </div>\n"""

    html = HTML_TEMPLATE.format(
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        summary_cards=summary_cards,
        stages_html=stages_html,
    )

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        f.write(html)

    print(f"Report generated: {output_file}")


if __name__ == "__main__":
    main()
