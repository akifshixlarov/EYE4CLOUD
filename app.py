"""
app.py

EYE4CLOUD — Azure Cloud Security Posture Management (CSPM) Scanner
Streamlit UI Dashboard (Hardened v2).
"""

import logging
from datetime import datetime
import pandas as pd
import streamlit as st

# HTTP və Azure SDK loglarında request/response sirlərinin sızmasının qarşısını almaq
for _log_name in ["azure", "urllib3", "msal", "azure.identity"]:
    logging.getLogger(_log_name).setLevel(logging.WARNING)

from core.dashboard_auth import require_login, render_logout
from core.scoring import calculate_scores
from core.remediation import get_remediation
from core.exceptions import accept_risk, revoke_acceptance, list_accepted_risks, accepted_keys_set
from core.history import delete_scan, clear_history
from core.security import is_public_mode, redact

from ui.auth_panel import init_session_state, render_connect_panel
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

# 1. Parol qoruması (.env-də tənzimlənibsə aktivləşir)
if not require_login():
    st.stop()

# 2. Sessiya idarəetməsi (in-memory credentials və tam per-session izolyasiya)
session_id = init_session_state()
public_mode = is_public_mode()
session_scans_store = st.session_state["session_scans"]
accepted_store = st.session_state["accepted_risks_store"]

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


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
        help="Heç bir Azure hesabı olmadan saxta nümunə məlumatları yükləyir",
    )
    st.session_state["demo_mode"] = demo_mode

    st.divider()

    if not demo_mode:
        # Runtime Azure Credentials Panel
        render_connect_panel()
        st.divider()

        # Skan başlat düyməsi
        st.subheader("⚡ Skan Əməliyyatı")
        if st.button("🔄 Yeni skan başlat", type="primary", width="stretch", key="btn_run_scan"):
            active_creds = st.session_state.get("azure_creds")
            if public_mode and not active_creds:
                st.error("Açıq rejimdə skan aparmaq üçün əvvəlcə 'Connect to Azure' bölməsindən məlumatlarınızı daxil edin.")
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
                    logging.exception("Skan zamanı gözlənilməz xəta: %s", redact(str(e)))
                    st.error("Skan zamanı xəta baş verdi. Texniki detallar təhlükəsiz şəkildə server log-una yazıldı.")
    else:
        st.info("💡 **Demo rejimi aktivdir.** Azure bağlantısı tələb olunmur, realistik saxta məlumatlar göstərilir.")
        if st.button("🔄 Demo məlumatları yenilə", width="stretch"):
            st.rerun()

    st.divider()

    # Skan tarixçəsi
    available_scans = get_available_scans(session_id, is_demo=demo_mode, session_scans_store=session_scans_store)
    st.subheader("📂 Skan Tarixçəsi")
    st.caption(f"Cari sessiya üzrə skan sayı: {len(available_scans)}")

    if available_scans:
        scan_names = [name for name, _ in reversed(available_scans)]
        selected_name = st.selectbox("Baxılacaq skan", scan_names, key="selected_scan_name")

        if not demo_mode:
            col_del, col_clear = st.columns(2)
            with col_del:
                if st.button("🗑️ Bunu sil", width="stretch"):
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
                if st.button("🧹 Təmizlə", width="stretch"):
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
            <h2 style="color: #2dd4bf; margin-bottom: 10px;">Hələ heç bir skan aparılmayıb</h2>
            <p style="color: #94a3b8; max-width: 600px; margin: 0 auto 20px auto;">
                Azure bulud mühitinizin təhlükəsizlik vəziyyətini (Storage, NSG, Key Vault, VM, Dependencies)
                yoxlamaq üçün sol paneldən Service Principal məlumatlarınızı daxil edib <strong>"Yeni skan başlat"</strong> düyməsini sıxın.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.write("")
    col_demo_btn, _ = st.columns([1, 2])
    with col_demo_btn:
        if st.button("🎮 Nümunə məlumatlarla dərhal bax (Demo Mode)", type="primary", width="stretch"):
            st.session_state["demo_mode"] = True
            st.rerun()
    st.stop()

# Seçilmiş skan məlumatı
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

# Başlıq və Status Paneli
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
        f'Skan tarixi: <b>{scan_time}</b><br>Subscription: <code>{sub_label}</code>'
        f'</div>',
        unsafe_allow_html=True,
    )

st.markdown("---")

azure_findings = [f for f in selected_scan.get("findings", []) if f.get("category") != "Dependency"]
dependency_findings = [f for f in selected_scan.get("findings", []) if f.get("category") == "Dependency"]

tab_overview, tab_findings, tab_history, tab_deps, tab_accepted = st.tabs(
    ["📊 Overview", "🔍 Findings", "📂 History", "📦 Dependencies", "✅ Accepted Risks"]
)


# ============================================================================
# TAB 1: OVERVIEW
# ============================================================================
with tab_overview:
    # 1. Gauge və Donut qrafikləri
    chart_col1, chart_col2 = st.columns([1, 1])
    with chart_col1:
        st.plotly_chart(get_gauge_chart(scores["overall"]), width="stretch")
    with chart_col2:
        st.plotly_chart(get_severity_donut(scores["findings_by_severity"]), width="stretch")

    # 2. KPI Cards
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric(
            label="Ümumi Tapıntı",
            value=len(selected_scan.get("findings", [])),
        )
    with kpi2:
        high_cnt = scores["findings_by_severity"].get("High", 0)
        st.metric(
            label="🔴 Kritik / Yüksək Risk",
            value=high_cnt,
            delta="Diqqət tələb edir" if high_cnt > 0 else "Təmiz",
            delta_color="inverse" if high_cnt > 0 else "normal",
        )
    with kpi3:
        med_cnt = scores["findings_by_severity"].get("Medium", 0)
        low_cnt = scores["findings_by_severity"].get("Low", 0)
        st.metric(
            label="🟡 Orta / 🟢 Aşağı",
            value=f"{med_cnt} / {low_cnt}",
        )
    with kpi4:
        if diff_data:
            chg = diff_data["score_change"]
            delta_str = f"+{chg}" if chg > 0 else str(chg)
            st.metric(
                label="Score Dəyişimi",
                value=f"{scores['overall']}/100",
                delta=f"{delta_str} bənd",
            )
        else:
            st.metric(label="Score Dəyişimi", value="—", delta="İlk skan")

    st.markdown("---")

    # 3. Kateqoriyalar üzrə vəziyyət
    st.subheader("🛡️ Resurs Kateqoriyaları üzrə Posture")
    cat_items = list(scores.get("by_category", {}).items())
    if cat_items:
        cat_cols = st.columns(len(cat_items))
        for col, (cat_name, cat_score) in zip(cat_cols, cat_items):
            with col:
                st.metric(
                    label=f"{_score_color(cat_score)} {cat_name}",
                    value=f"{cat_score}/100",
                )

    st.markdown("---")

    # 4. Son iki skan müqayisəsi (Diff)
    st.subheader("🔄 Skan Müqayisəsi (Son iki skan arası)")
    if diff_data:
        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.markdown(f"**🆕 Yeni yaranan tapıntılar ({len(diff_data['new_findings'])})**")
            if diff_data["new_findings"]:
                for f in diff_data["new_findings"]:
                    st.error(f"**{f['resource']}** ({f['category']}): {f['issue']}")
            else:
                st.success("Yeni yaranan risk yoxdur! 🎉")

        with d_col2:
            st.markdown(f"**✅ Həll olunan tapıntılar ({len(diff_data['resolved_findings'])})**")
            if diff_data["resolved_findings"]:
                for f in diff_data["resolved_findings"]:
                    st.success(f"**{f['resource']}** ({f['category']}): {f['issue']}")
            else:
                st.caption("Son skandan bəri həll olunan tapıntı yoxdur.")
    else:
        st.info("Müqayisə və dəyişiklik dinamikası üçün ən azı 2 skan lazımdır.")

    # 5. Trend xətti
    if len(trend_history) > 1:
        st.markdown("---")
        st.subheader("📈 Posture Score Trendi")
        st.plotly_chart(get_trend_chart(trend_history), width="stretch")


# ============================================================================
# TAB 2: FINDINGS
# ============================================================================
with tab_findings:
    st.subheader("🔍 Azure Konfiqurasiya Tapıntıları")

    if not azure_findings:
        st.success("Heç bir Azure konfiqurasiya problemi tapılmadı! Bulud mühitiniz əla qorunur. 🎉")
    else:
        # Top 5 Risks Bölməsi
        st.markdown("#### 🚨 Ən Yüksək Təsirli Risklər (Top Risks)")
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

        # Kateqoriyalar üzrə paylanma qrafiki
        cat_chart_col, _ = st.columns([1, 1])
        with cat_chart_col:
            st.plotly_chart(get_category_bar(azure_findings), width="stretch")

        st.markdown("---")

        # Filtrlər və Axtarış
        st.markdown("#### ⚙️ Filtrlər və Axtarış")
        f_search_col, f_sev_col, f_cat_col, f_rg_col = st.columns([2, 1, 1, 1])

        with f_search_col:
            search_query = st.text_input("Axtarış", placeholder="Resurs adı, check, xəta və ya CIS...", label_visibility="collapsed")

        # Mövcud dəyərlər
        all_sevs = ["High", "Medium", "Low"]
        all_cats = sorted(list({f.get("category", "") for f in azure_findings if f.get("category")}))
        all_rgs = sorted(list({f.get("resource_group", "") for f in azure_findings if f.get("resource_group")}))

        with f_sev_col:
            selected_sevs = st.multiselect("Severity", options=all_sevs, default=all_sevs, placeholder="Severity seçin")
        with f_cat_col:
            selected_cats = st.multiselect("Kateqoriya", options=all_cats, default=all_cats, placeholder="Kateqoriya")
        with f_rg_col:
            selected_rgs = st.multiselect("Resource Group", options=all_rgs, default=all_rgs, placeholder="Resource Group")

        # Filtrləmə məntiqi
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

        st.caption(f"Göstərilən tapıntılar: {len(filtered_findings)} / {len(azure_findings)}")

        # Cədvəl
        if filtered_findings:
            df = pd.DataFrame(filtered_findings)
            df["status"] = df.apply(
                lambda r: "✅ Qəbul edilib" if (r["category"], r["resource"], r["check"]) in accepted else "",
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

            # Expandable Remediation və Risk Acceptance
            st.markdown("#### 🛠️ Həll Təlimatları (Remediation) və Risk Qəbulu")
            for finding in sorted(filtered_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 3)):
                f_key = (finding["category"], finding["resource"], finding["check"])
                is_accepted = f_key in accepted
                widget_key = f"{finding['category']}|{finding['resource']}|{finding['check']}"
                sev_icon = "🔴" if finding["severity"] == "High" else ("🟡" if finding["severity"] == "Medium" else "🟢")
                label = f"{'✅ [QƏBUL EDİLDİ] ' if is_accepted else ''}{sev_icon} {finding['resource']} — {finding['check']} ({finding['category']})"

                with st.expander(label):
                    st.markdown(f"**Xəta / Problem:** {finding['issue']}")
                    st.markdown(f"**Uyğunluq (Compliance):** `{finding.get('compliance', 'N/A')}` &nbsp;|&nbsp; **Resource Group:** `{finding.get('resource_group', 'N/A')}`")

                    remediation = get_remediation(finding)
                    st.info(f"💡 **Tövsiyə:** {remediation['advice']}")

                    if remediation.get("command"):
                        st.markdown("**CLI Düzəliş Əmri (Kopyalamaq üçün hazırdır):**")
                        st.code(remediation["command"], language="bash")

                    # Risk Acceptance Form
                    if not demo_mode:
                        if is_accepted:
                            if st.button("🚫 Riskin qəbulunu ləğv et", key=f"revoke_{widget_key}"):
                                revoke_acceptance(finding["category"], finding["resource"], finding["check"], store=accepted_store)
                                st.rerun()
                        else:
                            r_col1, r_col2 = st.columns([3, 1])
                            with r_col1:
                                reason = st.text_input("Qəbul səbəbi (audit üçün qeyd)", key=f"reason_{widget_key}")
                            with r_col2:
                                st.write("")
                                st.write("")
                                if st.button("✅ Riski qəbul et", key=f"accept_{widget_key}"):
                                    if reason.strip():
                                        accept_risk(finding, reason, store=accepted_store)
                                        st.rerun()
                                    else:
                                        st.warning("Zəhmət olmasa səbəb qeyd edin.")

            # Eksport Bölməsi
            st.markdown("---")
            st.markdown("#### 📥 Hesabatı Yüklə (Export)")
            exp_col1, exp_col2, exp_col3 = st.columns(3)

            with exp_col1:
                csv_data = export_csv(filtered_findings)
                st.download_button(
                    label="📥 CSV olaraq yüklə",
                    data=csv_data,
                    file_name=f"eye4cloud_findings_{scan_time[:10]}.csv",
                    mime="text/csv",
                    width="stretch",
                )

            with exp_col2:
                json_data = export_json(selected_scan)
                st.download_button(
                    label="📥 JSON olaraq yüklə",
                    data=json_data,
                    file_name=f"eye4cloud_scan_{scan_time[:10]}.json",
                    mime="application/json",
                    width="stretch",
                )

            with exp_col3:
                html_data = export_html_report(selected_scan, scores)
                st.download_button(
                    label="📄 Standalone HTML Hesabatı yüklə",
                    data=html_data,
                    file_name=f"eye4cloud_report_{scan_time[:10]}.html",
                    mime="text/html",
                    width="stretch",
                )
        else:
            st.info("Axtarış və ya filtrlərə uyğun heç bir tapıntı tapılmadı.")


# ============================================================================
# TAB 3: HISTORY
# ============================================================================
with tab_history:
    st.subheader("📂 Skan Tarixçəsi və Nəticələr")
    history_rows = []
    for name, s in available_scans:
        s_scores = calculate_scores(s.get("findings", []))
        history_rows.append({
            "Skan Adı": name,
            "Tarix (UTC)": datetime.fromisoformat(s["scan_time"]).strftime("%Y-%m-%d %H:%M"),
            "Tapıntı Sayı": len(s.get("findings", [])),
            "Posture Score": f"{s_scores['overall']}/100",
            "High": s_scores["findings_by_severity"].get("High", 0),
            "Medium": s_scores["findings_by_severity"].get("Medium", 0),
            "Low": s_scores["findings_by_severity"].get("Low", 0),
        })

    if history_rows:
        st.dataframe(pd.DataFrame(history_rows), width="stretch", hide_index=True)
    st.caption("Fərdi skanları seçmək və ya silmək üçün sol paneldəki idarəetmə elementlərindən istifadə edin.")


# ============================================================================
# TAB 4: DEPENDENCIES
# ============================================================================
with tab_deps:
    st.subheader("📦 Asılılıqlar və Kitabxana Təhlükəsizliyi (PyPI CVE)")
    if dependency_findings:
        df_dep = pd.DataFrame(dependency_findings)
        df_dep["_sort"] = df_dep["severity"].map(SEVERITY_ORDER)
        df_dep = df_dep.sort_values("_sort").drop(columns="_sort")

        st.dataframe(
            df_dep.style.apply(_severity_style, axis=1),
            width="stretch",
            hide_index=True,
        )

        csv_dep = export_csv(dependency_findings)
        st.download_button(
            "📥 Dependencies CSV yüklə",
            csv_dep,
            "dependency_findings.csv",
            "text/csv",
            key="dep_csv_btn",
            width="stretch",
        )

        st.markdown("---")
        st.markdown("#### 🛠️ Təhlükəsizlik Tövsiyələri")
        for finding in sorted(dependency_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Low"), 3)):
            with st.expander(f"{finding['resource']} — {finding['check']}"):
                remediation = get_remediation(finding)
                st.write(remediation["advice"])
                if remediation.get("command"):
                    st.code(remediation["command"], language="bash")
    else:
        st.caption("Dependency tapıntısı yoxdur — bilinən CVE zəifliyi aşkar edilmədi.")


# ============================================================================
# TAB 5: ACCEPTED RISKS
# ============================================================================
with tab_accepted:
    st.subheader("✅ Qəbul Edilmiş Risklər (Exceptions)")
    accepted_risks = list_accepted_risks(store=accepted_store)
    if accepted_risks:
        st.dataframe(pd.DataFrame(accepted_risks), width="stretch", hide_index=True)
        st.caption("Qəbul edilmiş risklərin statusunu 'Findings' bölməsindəki təlimatlardan ləğv edə bilərsiniz.")
    else:
        st.caption("Hələ heç bir risk qəbul edilməyib.")
