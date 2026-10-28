"""
app.py

EYE4CLOUD — Azure Cloud Security Posture Management (CSPM) Scanner
Streamlit UI Dashboard (Hardened v2).
"""

import logging
from datetime import datetime
import pandas as pd
import streamlit as st

# Prevent request/response secrets from leaking into HTTP and Azure SDK logs
for _log_name in ["azure", "urllib3", "msal", "azure.identity"]:
    logging.getLogger(_log_name).setLevel(logging.WARNING)

from core.dashboard_auth import require_login, render_logout
from core.scoring import calculate_scores
from core.remediation import get_remediation
from core.exceptions import accept_risk, revoke_acceptance, list_accepted_risks, accepted_keys_set
from core.history import delete_scan, clear_history
from core.security import is_public_mode, redact
from core.scheduler import start_scheduler

from ui.auth_panel import init_session_state, render_connect_panel
from ui.automation_panel import render_automation_panel
from ui.scanner_runner import execute_parallel_scan
from ui.charts import get_gauge_chart, get_severity_donut, get_category_bar, get_trend_chart
from ui.export import export_csv, export_json, export_html_report
from ui.session_manager import get_available_scans, compute_scan_diff, compute_score_history

st.set_page_config(
    page_title="EYE4CLOUD — Azure CSPM Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 1. Password protection (enabled if configured in .env)
if not require_login():
    st.stop()

# 2. Session management (in-memory credentials and full per-session isolation)
session_id = init_session_state()
public_mode = is_public_mode()
session_scans_store = st.session_state["session_scans"]
accepted_store = st.session_state["accepted_risks_store"]

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


@st.cache_resource
def _scheduler_thread():
    # cache_resource = one background scheduler per server process, not per session
    return start_scheduler()


if not public_mode:
    _scheduler_thread()


def _score_color(score: int) -> str:
    if score >= 80:
        return "🟢"
    if score >= 50:
        return "🟡"
    return "🔴"


def _severity_style(row):
    styles = {
        "High": "background-color: #4a1414; color: #ffb3b3; font-weight: 600",
        "Medium": "background-color: #4a3c14; color: #ffe08a; font-weight: 600",
        "Low": "background-color: #14401f; color: #a8e6b0; font-weight: 600",
    }
    style = styles.get(row["severity"], "")
    return [style] * len(row)


def _row_style(row):
    if row.get("status"):
        return ["background-color: #242933; color: #8892b0"] * len(row)
    return _severity_style(row)


# ============================================================================
# SIDEBAR
# ============================================================================
with st.sidebar:
    st.title("🛡️ EYE4CLOUD")
    st.caption("Azure Cloud Security Posture Management")

    if public_mode:
        st.markdown(
            '<span style="background: #ef4444; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">PUBLIC MODE (ISOLATED)</span>',
            unsafe_allow_html=True,
        )

    # Demo Mode Toggle
    demo_mode = st.toggle(
        "🎮 Demo Mode (Safe Preview)",
        value=st.session_state["demo_mode"],
        key="demo_toggle",
        help="Loads realistic sample data without any Azure account",
    )
    st.session_state["demo_mode"] = demo_mode

    st.divider()

    if not demo_mode:
        # Runtime Azure Credentials Panel
        render_connect_panel()
        st.divider()

        # Start scan button
        st.subheader("⚡ Scan")
        if st.button("🔄 Start new scan", type="primary", width="stretch", key="btn_run_scan"):
            active_creds = st.session_state.get("azure_creds")
            if public_mode and not active_creds:
                st.error("In public mode, connect via the 'Connect to Azure' panel before scanning.")
            else:
                try:
                    execute_parallel_scan(
                        session_id=session_id,
                        credentials=active_creds,
                        keep_connected=st.session_state.get("keep_connected", False),
                        session_scans_store=session_scans_store,
                    )
                    st.rerun()
                except PermissionError as e:
                    st.error(str(e))
                except RuntimeError as e:
                    st.error(str(e))
                except Exception as e:
                    logging.exception("Unexpected error during scan: %s", redact(str(e)))
                    st.error("An error occurred during the scan. Technical details were safely written to the server log.")

        # Scheduling and notifications need server credentials and disk - local mode only
        if not public_mode:
            st.divider()
            st.subheader("🤖 Automation")
            render_automation_panel()
    else:
        st.info("💡 **Demo mode is active.** No Azure connection required; realistic sample data is shown.")
        if st.button("🔄 Refresh demo data", width="stretch"):
            st.rerun()

    st.divider()

    # Scan history
    available_scans = get_available_scans(session_id, is_demo=demo_mode, session_scans_store=session_scans_store)
    st.subheader("📂 Scan History")
    st.caption(f"Scans in this session: {len(available_scans)}")

    if available_scans:
        scan_names = [name for name, _ in reversed(available_scans)]
        selected_name = st.selectbox("Scan to view", scan_names, key="selected_scan_name")

        if not demo_mode:
            col_del, col_clear = st.columns(2)
            with col_del:
                if st.button("🗑️ Delete this scan", width="stretch"):
                    if public_mode:
                        st.session_state["session_scans"] = [
                            s for s in session_scans_store
                            if s.get("scan_time") != next((d.get("scan_time") for n, d in available_scans if n == selected_name), None)
                        ]
                    else:
                        matched_file = next((name for name, _ in available_scans if name == selected_name), None)
                        if matched_file:
                            from core.history import RESULTS_DIR
                            delete_scan(RESULTS_DIR / matched_file)
                    st.rerun()
            with col_clear:
                if st.button("🧹 Clear", width="stretch"):
                    session_scans_store.clear()
                    if not public_mode:
                        clear_history()
                    st.rerun()
    else:
        selected_name = None

    st.divider()
    render_logout()


# ============================================================================
# MAIN CONTENT AREA
# ============================================================================
available_scans = get_available_scans(session_id, is_demo=demo_mode, session_scans_store=session_scans_store)

if not available_scans:
    st.title("🛡️ EYE4CLOUD — Azure Misconfiguration Scanner")
    st.markdown("---")

    st.markdown(
        """
        <div style="background-color: #151a21; border: 1px solid #272f3d; border-radius: 10px; padding: 30px; text-align: center; margin-top: 20px;">
            <h2 style="color: #2dd4bf; margin-bottom: 10px;">No scans yet</h2>
            <p style="color: #94a3b8; max-width: 600px; margin: 0 auto 20px auto;">
                To check the security posture of your Azure environment (Storage, NSG, Key Vault, VM),
                connect to Azure from the left panel and click <strong>"Start new scan"</strong>,
                or turn on <strong>"Demo Mode"</strong> to explore sample data.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# Selected scan data
selected_scan = next(
    (data for name, data in available_scans if name == selected_name),
    available_scans[-1][1],
)

raw_scans_list = [data for _, data in available_scans]
diff_data = compute_scan_diff(raw_scans_list)
trend_history = compute_score_history(raw_scans_list)

accepted = accepted_keys_set(store=accepted_store)
scores = calculate_scores(selected_scan.get("findings", []), accepted_keys=accepted)
scan_time = datetime.fromisoformat(selected_scan["scan_time"]).strftime("%Y-%m-%d %H:%M UTC")

subs = selected_scan.get("subscription_ids") or [selected_scan.get("subscription_id", "—")]
sub_label = ", ".join(subs)

# Header and status panel
col_title, col_meta = st.columns([3, 2])
with col_title:
    st.title("🛡️ Azure Security Posture Dashboard")
with col_meta:
    if demo_mode:
        st.markdown(
            '<div style="text-align: right; margin-top: 15px;">'
            '<span style="background: #2dd4bf; color: #0b0f14; padding: 4px 10px; border-radius: 20px; font-weight: bold; font-size: 13px;">DEMO MODE</span>'
            '</div>',
            unsafe_allow_html=True,
        )
    st.markdown(
        f'<div style="text-align: right; color: #94a3b8; font-size: 13px;">'
        f'Scan time: <b>{scan_time}</b><br>Subscription: <code>{sub_label}</code>'
        f'</div>',
        unsafe_allow_html=True,
    )

st.markdown("---")

# Check modules that failed as a whole (e.g. no permission, provider not registered)
scan_errors = selected_scan.get("errors") or []
if scan_errors:
    st.warning(
        f"⚠️ {len(scan_errors)} check module(s) could not run in this scan - their results are missing:\n\n"
        + "\n".join(f"- {e}" for e in scan_errors)
    )

# Older saved scans may still contain "Dependency" findings - that check was removed
azure_findings = [f for f in selected_scan.get("findings", []) if f.get("category") != "Dependency"]

tab_overview, tab_findings, tab_history, tab_accepted = st.tabs(
    ["📊 Overview", "🔍 Findings", "📂 History", "✅ Accepted Risks"]
)


# ============================================================================
# TAB 1: OVERVIEW
# ============================================================================
with tab_overview:
    # 1. Gauge and donut charts
    chart_col1, chart_col2 = st.columns([1, 1])
    with chart_col1:
        st.plotly_chart(get_gauge_chart(scores["overall"]), width="stretch")
    with chart_col2:
        st.plotly_chart(get_severity_donut(scores["findings_by_severity"]), width="stretch")

    # 2. KPI Cards
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric(
            label="Total Findings",
            value=len(selected_scan.get("findings", [])),
        )
    with kpi2:
        high_cnt = scores["findings_by_severity"].get("High", 0)
        st.metric(
            label="🔴 Critical / High Risk",
            value=high_cnt,
            delta="Needs attention" if high_cnt > 0 else "Clean",
            delta_color="inverse" if high_cnt > 0 else "normal",
        )
    with kpi3:
        med_cnt = scores["findings_by_severity"].get("Medium", 0)
        low_cnt = scores["findings_by_severity"].get("Low", 0)
        st.metric(
            label="🟡 Medium / 🟢 Low",
            value=f"{med_cnt} / {low_cnt}",
        )
    with kpi4:
        if diff_data:
            chg = diff_data["score_change"]
            delta_str = f"+{chg}" if chg > 0 else str(chg)
            st.metric(
                label="Score Change",
                value=f"{scores['overall']}/100",
                delta=f"{delta_str} pts",
            )
        else:
            st.metric(label="Score Change", value="—", delta="First scan")

    st.markdown("---")

    # 3. Posture by category
    st.subheader("🛡️ Posture by Resource Category")
    cat_items = sorted(scores.get("by_category", {}).items())
    # Rows of at most 4 cards - one row for every category gets too cramped
    for row_start in range(0, len(cat_items), 4):
        row_items = cat_items[row_start:row_start + 4]
        for col, (cat_name, cat_score) in zip(st.columns(4), row_items):
            with col:
                st.metric(
                    label=f"{_score_color(cat_score)} {cat_name}",
                    value=f"{cat_score}/100",
                )

    st.markdown("---")

    # 4. Diff of the last two scans
    st.subheader("🔄 Scan Comparison (last two scans)")
    if diff_data:
        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown(f"**🆕 New findings ({len(diff_data['new_findings'])})**")
            if diff_data["new_findings"]:
                for f in diff_data["new_findings"]:
                    st.error(f"**{f['resource']}** ({f['category']}): {f['issue']}")
            else:
                st.success("No new risks! 🎉")

        with d_col2:
            st.markdown(f"**✅ Resolved findings ({len(diff_data['resolved_findings'])})**")
            if diff_data["resolved_findings"]:
                for f in diff_data["resolved_findings"]:
                    st.success(f"**{f['resource']}** ({f['category']}): {f['issue']}")
            else:
                st.caption("No findings resolved since the last scan.")
    else:
        st.info("At least 2 scans are needed for comparison and trends.")

    # 5. Trend line
    if len(trend_history) > 1:
        st.markdown("---")
        st.subheader("📈 Posture Score Trend")
        st.plotly_chart(get_trend_chart(trend_history), width="stretch")


# ============================================================================
# TAB 2: FINDINGS
# ============================================================================
with tab_findings:
    st.subheader("🔍 Azure Configuration Findings")

    if not azure_findings:
        st.success("No Azure configuration issues found! Your cloud environment is well protected. 🎉")
    else:
        # Top 5 risks section
        st.markdown("#### 🚨 Top Risks")
        sorted_by_risk = sorted(
            azure_findings,
            key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "Low"), 3), x.get("resource", "")),
        )
        top_5 = sorted_by_risk[:5]

        top_cols = st.columns(min(len(top_5), 5))
        for col, f in zip(top_cols, top_5):
            with col:
                sev = f.get("severity", "Low")
                border_color = "#ef4444" if sev == "High" else "#f59e0b"
                st.markdown(
                    f"""
                    <div style="background: #151a21; border-top: 3px solid {border_color}; border-radius: 6px; padding: 12px; height: 140px; overflow: hidden;">
                        <span style="font-size: 11px; font-weight: bold; color: {border_color}; text-transform: uppercase;">{sev} Risk</span><br>
                        <strong style="color: #ffffff; font-size: 13px;">{f.get('resource')}</strong><br>
                        <span style="font-size: 12px; color: #94a3b8;">{f.get('check')}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("---")

        # Distribution by category chart
        cat_chart_col, _ = st.columns([1, 1])
        with cat_chart_col:
            st.plotly_chart(get_category_bar(azure_findings), width="stretch")

        st.markdown("---")

        # Filters and search
        st.markdown("#### ⚙️ Filters & Search")
        f_search_col, f_sev_col, f_cat_col, f_rg_col = st.columns([2, 1, 1, 1])

        with f_search_col:
            search_query = st.text_input("Search", placeholder="Resource name, check, issue or CIS...", label_visibility="collapsed")

        # Available values
        all_sevs = ["High", "Medium", "Low"]
        all_cats = sorted(list({f.get("category", "") for f in azure_findings if f.get("category")}))
        all_rgs = sorted(list({f.get("resource_group", "") for f in azure_findings if f.get("resource_group")}))

        with f_sev_col:
            selected_sevs = st.multiselect("Severity", options=all_sevs, default=all_sevs, placeholder="Select severity")
        with f_cat_col:
            selected_cats = st.multiselect("Category", options=all_cats, default=all_cats, placeholder="Category")
        with f_rg_col:
            selected_rgs = st.multiselect("Resource Group", options=all_rgs, default=all_rgs, placeholder="Resource Group")

        # Filtering logic
        filtered_findings = []
        for f in azure_findings:
            if selected_sevs and f.get("severity") not in selected_sevs:
                continue
            if selected_cats and f.get("category") not in selected_cats:
                continue
            if selected_rgs and f.get("resource_group") not in selected_rgs:
                continue
            if search_query.strip():
                q = search_query.strip().lower()
                blob = f"{f.get('resource','')} {f.get('check','')} {f.get('issue','')} {f.get('compliance','')} {f.get('category','')}".lower()
                if q not in blob:
                    continue
            filtered_findings.append(f)

        st.caption(f"Showing findings: {len(filtered_findings)} / {len(azure_findings)}")

        # Table
        if filtered_findings:
            df = pd.DataFrame(filtered_findings)
            df["status"] = df.apply(
                lambda r: "✅ Accepted" if (r["category"], r["resource"], r["check"]) in accepted else "",
                axis=1,
            )
            df["_sort"] = df["severity"].map(SEVERITY_ORDER)
            df = df.sort_values("_sort").drop(columns="_sort")

            display_cols = [c for c in ["severity", "category", "resource", "resource_group", "check", "compliance", "status"] if c in df.columns]

            st.dataframe(
                df[display_cols].style.apply(_row_style, axis=1),
                width="stretch",
                hide_index=True,
            )

            st.markdown("---")

            # Expandable remediation and risk acceptance
            st.markdown("#### 🛠️ Remediation & Risk Acceptance")
            for finding in sorted(filtered_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 3)):
                f_key = (finding["category"], finding["resource"], finding["check"])
                is_accepted = f_key in accepted
                widget_key = f"{finding['category']}|{finding['resource']}|{finding['check']}"
                sev_icon = "🔴" if finding["severity"] == "High" else ("🟡" if finding["severity"] == "Medium" else "🟢")
                label = f"{'✅ [ACCEPTED] ' if is_accepted else ''}{sev_icon} {finding['resource']} — {finding['check']} ({finding['category']})"

                with st.expander(label):
                    st.markdown(f"**Issue:** {finding['issue']}")
                    st.markdown(f"**Compliance:** `{finding.get('compliance', 'N/A')}` &nbsp;|&nbsp; **Resource Group:** `{finding.get('resource_group', 'N/A')}`")

                    remediation = get_remediation(finding)
                    st.info(f"💡 **Recommendation:** {remediation['advice']}")

                    if remediation.get("command"):
                        st.markdown("**CLI fix command (ready to copy):**")
                        st.code(remediation["command"], language="bash")

                    # Risk Acceptance Form
                    if not demo_mode:
                        if is_accepted:
                            if st.button("🚫 Revoke risk acceptance", key=f"revoke_{widget_key}"):
                                revoke_acceptance(finding["category"], finding["resource"], finding["check"], store=accepted_store)
                                st.rerun()
                        else:
                            r_col1, r_col2 = st.columns([3, 1])
                            with r_col1:
                                reason = st.text_input("Acceptance reason (audit note)", key=f"reason_{widget_key}")
                            with r_col2:
                                st.write("")
                                st.write("")
                                if st.button("✅ Accept risk", key=f"accept_{widget_key}"):
                                    if reason.strip():
                                        accept_risk(finding, reason, store=accepted_store)
                                        st.rerun()
                                    else:
                                        st.warning("Please provide a reason.")

            # Export section
            st.markdown("---")
            st.markdown("#### 📥 Download Report (Export)")
            exp_col1, exp_col2, exp_col3 = st.columns(3)

            with exp_col1:
                csv_data = export_csv(filtered_findings)
                st.download_button(
                    label="📥 Download as CSV",
                    data=csv_data,
                    file_name=f"eye4cloud_findings_{scan_time[:10]}.csv",
                    mime="text/csv",
                    width="stretch",
                )

            with exp_col2:
                json_data = export_json(selected_scan)
                st.download_button(
                    label="📥 Download as JSON",
                    data=json_data,
                    file_name=f"eye4cloud_scan_{scan_time[:10]}.json",
                    mime="application/json",
                    width="stretch",
                )

            with exp_col3:
                html_data = export_html_report(selected_scan, scores)
                st.download_button(
                    label="📄 Download standalone HTML report",
                    data=html_data,
                    file_name=f"eye4cloud_report_{scan_time[:10]}.html",
                    mime="text/html",
                    width="stretch",
                )
        else:
            st.info("No findings match the search or filters.")


# ============================================================================
# TAB 3: HISTORY
# ============================================================================
with tab_history:
    st.subheader("📂 Scan History & Results")
    history_rows = []
    for name, s in available_scans:
        s_scores = calculate_scores(s.get("findings", []))
        history_rows.append({
            "Scan Name": name,
            "Date (UTC)": datetime.fromisoformat(s["scan_time"]).strftime("%Y-%m-%d %H:%M"),
            "Findings": len(s.get("findings", [])),
            "Posture Score": f"{s_scores['overall']}/100",
            "High": s_scores["findings_by_severity"].get("High", 0),
            "Medium": s_scores["findings_by_severity"].get("Medium", 0),
            "Low": s_scores["findings_by_severity"].get("Low", 0),
        })

    if history_rows:
        st.dataframe(pd.DataFrame(history_rows), width="stretch", hide_index=True)
    st.caption("Use the controls in the left panel to select or delete individual scans.")


# ============================================================================
# TAB 4: ACCEPTED RISKS
# ============================================================================
with tab_accepted:
    st.subheader("✅ Accepted Risks (Exceptions)")
    accepted_risks = list_accepted_risks(store=accepted_store)
    if accepted_risks:
        st.dataframe(pd.DataFrame(accepted_risks), width="stretch", hide_index=True)
        st.caption("You can revoke accepted risks from the remediation panels in the 'Findings' tab.")
    else:
        st.caption("No risks accepted yet.")
