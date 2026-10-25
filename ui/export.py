"""
ui/export.py

Tapıntıların və skan nəticələrinin müxtəlif formatlarda eksportu:
- CSV
- JSON
- Standalone HTML Report (modern, offline oxuna bilən təhlükəsizlik hesabatı)
"""

import html
import json
import pandas as pd


def export_csv(findings: list[dict]) -> str:
    """Tapıntıları CSV formatında string kimi qaytarır."""
    if not findings:
        return ""
    df = pd.DataFrame(findings)
    return df.to_csv(index=False)


def export_json(scan_data: dict) -> str:
    """Skan məlumatını təmiz JSON kimi qaytarır (heç bir credential ehtiva etmir)."""
    # Təhlükəsizlik: yalnız icazə verilən açarları serializasiya edirik
    safe_data = {
        "scan_time": scan_data.get("scan_time"),
        "subscription_ids": scan_data.get("subscription_ids", []),
        "total_findings": scan_data.get("total_findings", len(scan_data.get("findings", []))),
        "findings": scan_data.get("findings", []),
    }
    return json.dumps(safe_data, indent=2, ensure_ascii=False)


def export_html_report(scan_data: dict, scores: dict) -> str:
    """
    Özündə bütün CSS və formatlamanı saxlayan standalone HTML hesabatı.
    İnternet bağlantısı olmadan da açılır və rahat çap/paylaşım üçün idealdır.
    """
    scan_time = scan_data.get("scan_time", "N/A")
    subs = ", ".join(scan_data.get("subscription_ids", ["—"]))
    findings = scan_data.get("findings", [])
    overall_score = scores.get("overall", 0)
    sev_counts = scores.get("findings_by_severity", {"High": 0, "Medium": 0, "Low": 0})

    if overall_score >= 80:
        score_badge = '<span class="score-badge score-good">Əla (80-100)</span>'
        score_color = "#10b981"
    elif overall_score >= 50:
        score_badge = '<span class="score-badge score-warning">Diqqət (50-79)</span>'
        score_color = "#f59e0b"
    else:
        score_badge = '<span class="score-badge score-danger">Kritik (0-49)</span>'
        score_color = "#ef4444"

    # Cədvəl sətirləri
    rows_html = []
    for f in findings:
        sev = html.escape(str(f.get("severity", "Low")))
        cat = html.escape(str(f.get("category", "General")))
        res = html.escape(str(f.get("resource", "—")))
        rg = html.escape(str(f.get("resource_group", "—")))
        chk = html.escape(str(f.get("check", "—")))
        issue = html.escape(str(f.get("issue", "—")))
        comp = html.escape(str(f.get("compliance", "N/A")))

        badge_class = f"badge-{sev.lower()}"
        rows_html.append(f"""
        <tr>
            <td><span class="badge {badge_class}">{sev}</span></td>
            <td><strong>{res}</strong><br><small class="text-muted">{rg}</small></td>
            <td>{cat}</td>
            <td>{chk}</td>
            <td>{issue}</td>
            <td><code>{comp}</code></td>
        </tr>
        """)

    rows_joined = "\n".join(rows_html) if rows_html else "<tr><td colspan='6' class='text-center'>Heç bir tapıntı yoxdur.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EYE4CLOUD - Azure Security Posture Report</title>
    <style>
        :root {{
            --bg: #0b0f14;
            --card-bg: #151a21;
            --border: #272f3d;
            --text: #e8eaed;
            --text-muted: #94a3b8;
            --primary: #2dd4bf;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 26px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .header .meta {{
            color: var(--text-muted);
            font-size: 13px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .kpi-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
        }}
        .kpi-title {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-size: 28px;
            font-weight: 700;
        }}
        .score-box {{
            color: {score_color};
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-high {{
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.4);
        }}
        .badge-medium {{
            background: rgba(245, 158, 11, 0.2);
            color: #fde68a;
            border: 1px solid rgba(245, 158, 11, 0.4);
        }}
        .badge-low {{
            background: rgba(16, 185, 129, 0.2);
            color: #a7f3d0;
            border: 1px solid rgba(16, 185, 129, 0.4);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            font-size: 14px;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #1a202c;
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        tr:hover td {{
            background: rgba(45, 212, 191, 0.04);
        }}
        code {{
            background: #222a36;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            color: #38bdf8;
        }}
        .text-muted {{ color: var(--text-muted); }}
        .text-center {{ text-align: center; }}
        .footer {{
            margin-top: 40px;
            padding-top: 15px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ EYE4CLOUD Security Report</h1>
                <div class="meta">Azure Cloud Security Posture Management (CSPM) Snapshot</div>
            </div>
            <div style="text-align: right;">
                <div class="meta">Skan tarixi: <strong>{scan_time}</strong></div>
                <div class="meta">Subscription(lar): <strong>{subs}</strong></div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Posture Score</div>
                <div class="kpi-value score-box">{overall_score}/100</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Ümumi Tapıntı</div>
                <div class="kpi-value">{len(findings)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">High Risk</div>
                <div class="kpi-value" style="color: var(--danger);">{sev_counts.get("High", 0)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Medium / Low</div>
                <div class="kpi-value" style="color: var(--warning);">{sev_counts.get("Medium", 0)} / <span style="color: var(--success);">{sev_counts.get("Low", 0)}</span></div>
            </div>
        </div>

        <h2 style="font-size: 18px; margin-bottom: 15px;">🔍 Təhlükəsizlik Tapıntıları</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 80px;">Severity</th>
                    <th>Resurs & Qrup</th>
                    <th>Kateqoriya</th>
                    <th>Yoxlama</th>
                    <th>Təsvir / Xəta</th>
                    <th>Uyğunluq</th>
                </tr>
            </thead>
            <tbody>
                {rows_joined}
            </tbody>
        </table>

        <div class="footer">
            EYE4CLOUD Avtomatlaşdırılmış Azure Misconfiguration Scanner &bull; Yalnız Oxuma (Read-Only) Rejimi
        </div>
    </div>
</body>
</html>"""
    return html_content
