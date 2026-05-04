#!/usr/bin/env python3
"""
Infrastructure Security Report Generator
==========================================
Generates three focused HTML reports:
  infra-security-report.html  — Executive summary
  trivy-detail.html           — Full Trivy findings
  checkov-detail.html         — Full Checkov policy violations
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ── Environment ────────────────────────────────────────────────────────────────
REPO_NAME          = os.environ.get('REPO_NAME', 'unknown')
GITLAB_REPO_PATH   = os.environ.get('GITLAB_REPO_PATH', 'unknown')
REPO_COMMIT        = os.environ.get('REPO_COMMIT', 'unknown')
GIT_BRANCH         = os.environ.get('GIT_BRANCH', 'unknown')
BUILD_NUMBER       = os.environ.get('BUILD_NUMBER', 'unknown')
BUILD_URL          = os.environ.get('BUILD_URL', '#')
PIPELINE_STATUS    = os.environ.get('PIPELINE_STATUS', 'UNKNOWN')
PIPELINE_REASON    = os.environ.get('PIPELINE_FAIL_REASON', '')
WORKSPACE          = os.environ.get('WORKSPACE', '.')

# Tool results
TRIVY_CRITICAL    = int(os.environ.get('TRIVY_CRITICAL', '0'))
TRIVY_HIGH        = int(os.environ.get('TRIVY_HIGH', '0'))
TRIVY_MISCONFIGS  = int(os.environ.get('TRIVY_MISCONFIGS', '0'))
TRIVY_SECRETS     = int(os.environ.get('TRIVY_SECRETS', '0'))
CHECKOV_FAILED    = int(os.environ.get('CHECKOV_FAILED', '0'))
CHECKOV_PASSED    = int(os.environ.get('CHECKOV_PASSED', '0'))
ANSIBLE_VIOLATIONS= int(os.environ.get('ANSIBLE_VIOLATIONS', '0'))
ANSIBLE_ERRORS    = int(os.environ.get('ANSIBLE_ERRORS', '0'))
TFLINT_ISSUES     = int(os.environ.get('TFLINT_ISSUES', '0'))
HADOLINT_ERRORS   = int(os.environ.get('HADOLINT_ERRORS', '0'))
HADOLINT_WARNINGS = int(os.environ.get('HADOLINT_WARNINGS', '0'))

HAS_TERRAFORM  = os.environ.get('HAS_TERRAFORM', 'false') == 'true'
HAS_ANSIBLE    = os.environ.get('HAS_ANSIBLE', 'false') == 'true'
HAS_DOCKERFILE = os.environ.get('HAS_DOCKERFILE', 'false') == 'true'
HAS_KUBERNETES = os.environ.get('HAS_KUBERNETES', 'false') == 'true'
HAS_COMPOSE    = os.environ.get('HAS_COMPOSE', 'false') == 'true'

NOW = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

# ── Base CSS ───────────────────────────────────────────────────────────────────
BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, sans-serif; font-size: 14px; color: #404040;
       background: #F8F9FA; line-height: 1.6; }
.container { max-width: 1100px; margin: 0 auto; padding: 24px; }
.header { background: #1A3A5C; color: white; padding: 28px 32px;
          border-radius: 8px; margin-bottom: 20px; }
.header h1 { font-size: 26px; font-weight: 700; }
.header .sub { font-size: 13px; opacity: 0.85; margin-top: 4px; }
.meta { display: grid; grid-template-columns: repeat(3,1fr);
        gap: 8px; margin-top: 16px; }
.meta-item { background: rgba(255,255,255,0.1); padding: 8px 12px;
             border-radius: 4px; }
.meta-item .label { font-size: 11px; text-transform: uppercase; opacity: 0.7; }
.meta-item .value { font-weight: 600; font-size: 13px; word-break: break-all; }
.status-bar { padding: 14px 20px; border-radius: 8px; margin-bottom: 20px;
              display: flex; align-items: center; gap: 16px; }
.s-label { font-size: 20px; font-weight: 700; }
.s-reason { font-size: 13px; color: #595959; }
.grid4 { display: grid; grid-template-columns: repeat(4,1fr);
         gap: 16px; margin-bottom: 20px; }
.card { background: white; border-radius: 8px; padding: 20px;
        text-align: center; border: 1px solid #E0E0E0; }
.card .count { font-size: 36px; font-weight: 700; }
.card .label { font-size: 12px; color: #595959;
               text-transform: uppercase; margin-top: 4px; }
.card.critical .count { color: #7B1F1F; }
.card.high     .count { color: #7B3F00; }
.card.medium   .count { color: #7B4F00; }
.card.info     .count { color: #1A3A5C; }
.section { background: white; border-radius: 8px; padding: 24px;
           margin-bottom: 20px; border: 1px solid #E0E0E0; }
.section h2 { font-size: 18px; font-weight: 600; color: #1A3A5C;
              padding-bottom: 10px; border-bottom: 2px solid #D6E4F0;
              margin-bottom: 14px; }
.section h3 { font-size: 14px; font-weight: 600; color: #595959;
              margin: 16px 0 8px; }
.tool-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 12px; }
.tool-card { border: 1px solid #E0E0E0; border-radius: 6px; padding: 16px; }
.tool-card h3 { font-size: 14px; font-weight: 600; color: #2E75B6;
                margin: 0 0 10px; }
.tool-card .row { font-size: 13px; color: #595959; margin: 3px 0; }
.link-btn { display: inline-block; margin-top: 10px; padding: 6px 14px;
            background: #EBF3FA; color: #1A3A5C; border-radius: 4px;
            font-size: 12px; font-weight: 600; text-decoration: none; }
.link-btn:hover { background: #D6E4F0; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #EBF3FA; color: #1A3A5C; font-weight: 600;
     padding: 10px 12px; text-align: left; border-bottom: 2px solid #D6E4F0; }
td { padding: 9px 12px; border-bottom: 1px solid #F0F0F0; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #FAFAFA; }
.mono { font-family: monospace; font-size: 12px; }
.badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.pill { background: #EBF3FA; color: #1A3A5C; padding: 2px 8px;
        border-radius: 10px; font-size: 11px; font-weight: 600; }
.empty { color: #888; font-style: italic; padding: 20px; text-align: center; }
.footer { text-align: center; font-size: 12px; color: #888;
          margin-top: 20px; padding: 16px; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 4px;
       font-size: 11px; font-weight: 600; margin: 2px;
       background: #EBF3FA; color: #1A3A5C; }
a { color: #2E75B6; text-decoration: none; }
a:hover { text-decoration: underline; }
"""

BADGE_COLORS = {
    'CRITICAL': ('#7B1F1F', '#FDECEA'),
    'HIGH':     ('#7B3F00', '#FFF0E0'),
    'MEDIUM':   ('#7B4F00', '#FFF3CD'),
    'LOW':      ('#1D6B5E', '#E1F5EE'),
    'ERROR':    ('#7B1F1F', '#FDECEA'),
    'WARNING':  ('#7B4F00', '#FFF3CD'),
    'INFO':     ('#1A3A5C', '#EBF3FA'),
    'SECRET':   ('#7B1F1F', '#FDECEA'),
    'PASSED':   ('#1E5631', '#D4EDDA'),
    'FAILED':   ('#7B1F1F', '#FDECEA'),
}

def badge(s):
    c = BADGE_COLORS.get(s.upper(), ('#404040', '#F2F2F2'))
    return (f'<span class="badge" '
            f'style="background:{c[1]};color:{c[0]};">{s}</span>')

def page_head(title):
    return (f'<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            f'<meta charset="UTF-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>{title}</title>\n'
            f'<style>{BASE_CSS}</style>\n</head>\n<body>\n<div class="container">\n')

def page_header(title, subtitle):
    iac_types = []
    if HAS_TERRAFORM:  iac_types.append('Terraform')
    if HAS_ANSIBLE:    iac_types.append('Ansible')
    if HAS_DOCKERFILE: iac_types.append('Dockerfile')
    if HAS_KUBERNETES: iac_types.append('Kubernetes')
    if HAS_COMPOSE:    iac_types.append('Docker Compose')
    types_str = ' · '.join(iac_types) if iac_types else 'No IaC detected'

    return f"""
  <div class="header">
    <h1>{title}</h1>
    <div class="sub">{subtitle}</div>
    <div class="meta">
      <div class="meta-item">
        <div class="label">Repository</div>
        <div class="value">{GITLAB_REPO_PATH}</div>
      </div>
      <div class="meta-item">
        <div class="label">Branch</div>
        <div class="value">{GIT_BRANCH}</div>
      </div>
      <div class="meta-item">
        <div class="label">Commit</div>
        <div class="value">{REPO_COMMIT[:12]}</div>
      </div>
      <div class="meta-item">
        <div class="label">Build</div>
        <div class="value">#{BUILD_NUMBER}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scan date</div>
        <div class="value">{NOW}</div>
      </div>
      <div class="meta-item">
        <div class="label">IaC types detected</div>
        <div class="value" style="font-size:11px;">{types_str}</div>
      </div>
    </div>
  </div>
"""

def status_bar():
    passed = PIPELINE_STATUS == 'PASSED'
    bg     = '#D4EDDA' if passed else '#FDECEA'
    border = '#1E5631' if passed else '#7B1F1F'
    color  = '#1E5631' if passed else '#7B1F1F'
    label  = 'PASSED ✅' if passed else 'FAILED ❌'
    reason = PIPELINE_REASON if not passed else ''
    return (f'<div class="status-bar" '
            f'style="background:{bg};border-left:6px solid {border};">\n'
            f'  <div class="s-label" style="color:{color};">{label}</div>\n'
            f'  <div class="s-reason">'
            f'{"All infrastructure checks passed." if not reason else reason}'
            f'</div>\n</div>\n')

def page_footer():
    return (f'\n  <div class="footer">'
            f'Generated by the Jenkins infrastructure security pipeline'
            f' &nbsp;·&nbsp; '
            f'<a href="{BUILD_URL}">Build #{BUILD_NUMBER}</a>'
            f' &nbsp;·&nbsp; {NOW}'
            f'</div>\n</div>\n</body>\n</html>')


# ── Report 1: Executive summary ────────────────────────────────────────────────
def generate_summary():
    total_critical = TRIVY_CRITICAL + (1 if TRIVY_SECRETS > 0 else 0)
    total_high     = TRIVY_HIGH + CHECKOV_FAILED + ANSIBLE_ERRORS + HADOLINT_ERRORS
    total_medium   = TRIVY_MISCONFIGS + ANSIBLE_VIOLATIONS + TFLINT_ISSUES + HADOLINT_WARNINGS
    total_blocking = total_critical + total_high

    html  = page_head(f"Infrastructure Security Report — {REPO_NAME}")
    html += page_header(f"Infrastructure Security Report — {REPO_NAME}",
                        "Executive summary")
    html += status_bar()

    # Summary cards
    html += f"""
  <div class="grid4">
    <div class="card critical">
      <div class="count">{TRIVY_CRITICAL}</div>
      <div class="label">Critical CVEs</div>
    </div>
    <div class="card high">
      <div class="count">{TRIVY_HIGH}</div>
      <div class="label">High CVEs</div>
    </div>
    <div class="card medium">
      <div class="count">{CHECKOV_FAILED}</div>
      <div class="label">Policy violations</div>
    </div>
    <div class="card info">
      <div class="count">{TRIVY_SECRETS}</div>
      <div class="label">Secrets detected</div>
    </div>
  </div>
"""
    if TRIVY_SECRETS > 0:
        html += f"""
  <div style="background:#FDECEA;border-left:6px solid #7B1F1F;
              padding:14px 20px;border-radius:8px;margin-bottom:20px;">
    <strong style="color:#7B1F1F;">🔑 {TRIVY_SECRETS} secret(s) detected in repository files.</strong>
    Remove immediately and rotate all exposed credentials.
  </div>
"""

    # Tool summary cards
    html += '<div class="section"><h2>Tool results</h2><div class="tool-grid">\n'

    # Trivy
    html += f"""
  <div class="tool-card">
    <h3>Trivy</h3>
    <div class="row">{badge('CRITICAL')} {TRIVY_CRITICAL} critical CVEs</div>
    <div class="row">{badge('HIGH')} {TRIVY_HIGH} high CVEs</div>
    <div class="row">{badge('WARNING')} {TRIVY_MISCONFIGS} misconfigurations</div>
    <div class="row">{badge('SECRET')} {TRIVY_SECRETS} secrets</div>
    <a class="link-btn" href="trivy-detail.html">View full Trivy report</a>
  </div>
"""

    # Checkov
    checkov_status = 'FAILED' if CHECKOV_FAILED > 10 else ('WARNING' if CHECKOV_FAILED > 0 else 'PASSED')
    html += f"""
  <div class="tool-card">
    <h3>Checkov IaC</h3>
    <div class="row">{badge('FAILED' if CHECKOV_FAILED > 0 else 'PASSED')} {CHECKOV_FAILED} violations</div>
    <div class="row">{badge('PASSED')} {CHECKOV_PASSED} checks passed</div>
    <div class="row" style="margin-top:6px;color:#888;">
      Scanned: {'Terraform · ' if HAS_TERRAFORM else ''}{'Ansible · ' if HAS_ANSIBLE else ''}{'K8s · ' if HAS_KUBERNETES else ''}{'Compose · ' if HAS_COMPOSE else ''}{'Dockerfile' if HAS_DOCKERFILE else ''}
    </div>
    <a class="link-btn" href="checkov-detail.html">View full Checkov report</a>
  </div>
"""

    # Other tools
    other_items = []
    if HAS_ANSIBLE:
        other_items.append(f'<div class="row">{badge("ERROR" if ANSIBLE_ERRORS > 0 else "PASSED")} ansible-lint: {ANSIBLE_VIOLATIONS} violations ({ANSIBLE_ERRORS} errors)</div>')
    if HAS_TERRAFORM:
        other_items.append(f'<div class="row">{badge("WARNING" if TFLINT_ISSUES > 0 else "PASSED")} tflint: {TFLINT_ISSUES} issues</div>')
    if HAS_DOCKERFILE:
        other_items.append(f'<div class="row">{badge("ERROR" if HADOLINT_ERRORS > 0 else "PASSED")} Hadolint: {HADOLINT_ERRORS} errors · {HADOLINT_WARNINGS} warnings</div>')

    html += f"""
  <div class="tool-card">
    <h3>Linters</h3>
    {''.join(other_items) if other_items else '<div class="row" style="color:#888;">No applicable files detected</div>'}
  </div>
</div></div>
"""

    # Metadata
    html += f"""
  <div class="section">
    <h2>Scan metadata</h2>
    <table>
      <tr><th style="width:220px;">Item</th><th>Value</th></tr>
      <tr><td>Repository</td><td>{REPO_NAME}</td></tr>
      <tr><td>Path</td><td>{GITLAB_REPO_PATH}</td></tr>
      <tr><td>Commit SHA</td><td class="mono">{REPO_COMMIT}</td></tr>
      <tr><td>Branch</td><td>{GIT_BRANCH}</td></tr>
      <tr><td>Scan date</td><td>{NOW}</td></tr>
      <tr><td>Build</td><td>#{BUILD_NUMBER} &nbsp; <a href="{BUILD_URL}">{BUILD_URL}</a></td></tr>
      <tr><td>Pipeline status</td><td>{PIPELINE_STATUS}</td></tr>
      <tr><td>IaC types detected</td><td>
        {'<span class="tag">Terraform</span>' if HAS_TERRAFORM else ''}
        {'<span class="tag">Ansible</span>' if HAS_ANSIBLE else ''}
        {'<span class="tag">Dockerfile</span>' if HAS_DOCKERFILE else ''}
        {'<span class="tag">Kubernetes</span>' if HAS_KUBERNETES else ''}
        {'<span class="tag">Docker Compose</span>' if HAS_COMPOSE else ''}
      </td></tr>
    </table>
  </div>
"""
    html += page_footer()
    return html


# ── Report 2: Trivy detail ─────────────────────────────────────────────────────
def generate_trivy_detail():
    path = Path(WORKSPACE) / 'trivy-report.json'
    results = []
    if path.exists():
        try:
            data = json.loads(path.read_text())
            results = data.get('Results', [])
        except Exception as e:
            print(f"Warning: could not read trivy-report.json: {e}", file=sys.stderr)

    html  = page_head(f"Trivy Report — {REPO_NAME}")
    html += page_header(f"Trivy Security Report — {REPO_NAME}",
                        f"CVEs · Misconfigurations · Secrets")
    html += status_bar()

    for result in results:
        target = result.get('Target', 'unknown')
        vulns  = result.get('Vulnerabilities', [])
        miscon = result.get('Misconfigurations', [])
        secrets = result.get('Secrets', [])

        if not vulns and not miscon and not secrets:
            continue

        html += f'<div class="section"><h2>{target}</h2>\n'

        if secrets:
            html += f'<h3>🔑 Secrets — {len(secrets)}</h3>\n<table>\n'
            html += '<tr><th>Rule</th><th>Category</th><th>Match</th></tr>\n'
            for s in secrets:
                html += (f'<tr><td>{badge("SECRET")}&nbsp;{s.get("RuleID","")}</td>'
                         f'<td>{s.get("Category","")}</td>'
                         f'<td class="mono">{str(s.get("Match",""))[:60]}...</td></tr>\n')
            html += '</table>\n'

        if vulns:
            critical = [v for v in vulns if v.get('Severity') == 'CRITICAL']
            high     = [v for v in vulns if v.get('Severity') == 'HIGH']
            medium   = [v for v in vulns if v.get('Severity') == 'MEDIUM']

            for group, label in [(critical, 'Critical'), (high, 'High'), (medium, 'Medium')]:
                if not group:
                    continue
                sev = label.upper()
                html += f'<h3>{label} CVEs — {len(group)}</h3>\n<table>\n'
                html += '<tr><th style="width:140px;">CVE</th><th style="width:90px;">Severity</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Title</th></tr>\n'
                for v in group:
                    html += (f'<tr>'
                             f'<td class="mono">{v.get("VulnerabilityID","")}</td>'
                             f'<td>{badge(sev)}</td>'
                             f'<td class="mono">{v.get("PkgName","")}</td>'
                             f'<td class="mono">{v.get("InstalledVersion","")}</td>'
                             f'<td class="mono">{v.get("FixedVersion","N/A")}</td>'
                             f'<td style="font-size:12px;color:#595959;">{str(v.get("Title",""))[:80]}</td>'
                             f'</tr>\n')
                html += '</table>\n'

        if miscon:
            html += f'<h3>Misconfigurations — {len(miscon)}</h3>\n<table>\n'
            html += '<tr><th>ID</th><th>Severity</th><th>Title</th><th>Description</th></tr>\n'
            for m in miscon:
                sev = m.get('Severity', 'MEDIUM')
                html += (f'<tr>'
                         f'<td class="mono">{m.get("ID","")}</td>'
                         f'<td>{badge(sev)}</td>'
                         f'<td>{m.get("Title","")}</td>'
                         f'<td style="font-size:12px;color:#595959;">{str(m.get("Description",""))[:120]}</td>'
                         f'</tr>\n')
            html += '</table>\n'

        html += '</div>\n'

    if not results:
        html += '<div class="section"><p class="empty">No findings — repository is clean.</p></div>\n'

    html += page_footer()
    return html


# ── Report 3: Checkov detail ───────────────────────────────────────────────────
def generate_checkov_detail():
    path = Path(WORKSPACE) / 'checkov-report.json'
    data_list = []
    if path.exists():
        try:
            raw = json.loads(path.read_text())
            data_list = raw if isinstance(raw, list) else [raw]
        except Exception as e:
            print(f"Warning: could not read checkov-report.json: {e}", file=sys.stderr)

    html  = page_head(f"Checkov Report — {REPO_NAME}")
    html += page_header(f"Checkov IaC Policy Report — {REPO_NAME}",
                        f"{CHECKOV_FAILED} violations · {CHECKOV_PASSED} passed")
    html += status_bar()

    for section in data_list:
        check_type    = section.get('check_type', 'IaC')
        failed_checks = section.get('results', {}).get('failed_checks', [])
        passed_checks = section.get('results', {}).get('passed_checks', [])

        if not failed_checks and not passed_checks:
            continue

        html += f'<div class="section"><h2>{check_type.upper()} — {len(failed_checks)} violations</h2>\n'

        if failed_checks:
            html += '<table>\n'
            html += '<tr><th style="width:160px;">Check ID</th><th>Resource</th><th>File</th><th>Description</th></tr>\n'
            for c in failed_checks:
                resource = c.get('resource', '')
                file_path = c.get('file_path', '')
                line = c.get('file_line_range', ['?', '?'])
                line_str = f"L{line[0]}-{line[1]}" if isinstance(line, list) else str(line)
                check_id = c.get('check_id', '')
                check_name = c.get('check', {})
                if isinstance(check_name, dict):
                    check_name = check_name.get('name', check_id)
                html += (f'<tr>'
                         f'<td><span class="pill">{check_id}</span></td>'
                         f'<td class="mono" style="font-size:11px;">{resource}</td>'
                         f'<td class="mono" style="font-size:11px;">{file_path} {line_str}</td>'
                         f'<td style="font-size:12px;color:#595959;">{str(check_name)[:100]}</td>'
                         f'</tr>\n')
            html += '</table>\n'
        else:
            html += '<p class="empty">No violations for this check type.</p>\n'

        html += '</div>\n'

    if not data_list:
        html += '<div class="section"><p class="empty">No Checkov results found.</p></div>\n'

    html += page_footer()
    return html


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    ws = Path(WORKSPACE)

    print("Generating infra-security-report.html (summary)...")
    (ws / 'infra-security-report.html').write_text(
        generate_summary(), encoding='utf-8')

    print("Generating trivy-detail.html...")
    (ws / 'trivy-detail.html').write_text(
        generate_trivy_detail(), encoding='utf-8')

    print("Generating checkov-detail.html...")
    (ws / 'checkov-detail.html').write_text(
        generate_checkov_detail(), encoding='utf-8')

    print("Done.")
    print(f"  {ws}/infra-security-report.html")
    print(f"  {ws}/trivy-detail.html")
    print(f"  {ws}/checkov-detail.html")
