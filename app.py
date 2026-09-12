"""
app.py

Azure Misconfiguration Scanner - Streamlit UI.

`streamlit run app.py` ile ise salinir. Butun agir is (Azure-a sorgu,
scoring, diff) core/ ve checks/ modullarindadir - bu fayl yalnizca
onlari cagirib neticeni gorsel sekilde teqdim edir.
"""

import logging
from datetime import datetime

import pandas as pd
import streamlit as st

from core.scanner import run_scan
from core.scoring import calculate_scores
from core.diff import compare_last_two_scans, score_history
from core.history import list_scan_files, load_scan, delete_scan, clear_history
from core.remediation import get_remediation
from core.exceptions import accept_risk, revoke_acceptance, list_accepted_risks, accepted_keys_set
from core.dashboard_auth import require_login, render_logout

st.set_page_config(
    page_title="Azure Misconfiguration Scanner",
    page_icon="🛡️",
    layout="wide",
)

# Parol qorumasi .env-de konfiqurasiya edilmeyibse bu addim heç nə etmir
if not require_login():
    st.stop()

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _score_color(score: int) -> str:
    if score >= 80:
        return "🟢"
    if score >= 50:
        return "🟡"
    return "🔴"


def _severity_style(row):
    # Dark-theme-uyğun: tünd fon + açıq mətn rəngi, ağ fon üzərinə solğun
    # yazı problemi olmasın deyə hər ikisini birlikdə təyin edirik
    styles = {
        "High": "background-color: #4a1414; color: #ffb3b3; font-weight: 600",
        "Medium": "background-color: #4a3c14; color: #ffe08a; font-weight: 600",
        "Low": "background-color: #14401f; color: #a8e6b0; font-weight: 600",
    }
    style = styles.get(row["severity"], "")
    return [style] * len(row)


def _row_style(row):
    # Qəbul edilmiş risklər boz/solğun gostərilir - severity rənginə üstün gəlir
    if row.get("status"):
        return ["background-color: #2a2a2a; color: #888888"] * len(row)
    return _severity_style(row)


def _remediation_and_acceptance_section(findings: list[dict], accepted: set, allow_accept: bool) -> None:
    """
    Bir finding siyahisi ucun remediation expander-lerini gostərir.
    `allow_accept=True` olarsa, hər expander-ə qəbul et/ləğv et düymələri
    də əlavə olunur (Azure check-ləri üçün; dependency tapıntıları üçün istifadə olunmur).
    """
    for finding in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 3)):
        key = (finding["category"], finding["resource"], finding["check"])
        finding_is_accepted = key in accepted
        widget_key = f"{finding['category']}|{finding['resource']}|{finding['check']}"
        label = f"{'✅ ' if finding_is_accepted else ''}{finding['resource']} — {finding['check']}"

        with st.expander(label):
            remediation = get_remediation(finding)
            st.write(remediation["advice"])
            if remediation["command"]:
                st.code(remediation["command"], language="bash")

            if not allow_accept:
                continue

            if finding_is_accepted:
                if st.button("🚫 Qəbulu ləğv et", key=f"revoke_{widget_key}"):
                    revoke_acceptance(finding["category"], finding["resource"], finding["check"])
                    st.rerun()
            else:
                reason = st.text_input("Qəbul səbəbi", key=f"reason_{widget_key}")
                if st.button("✅ Riski qəbul et", key=f"accept_{widget_key}"):
                    if reason.strip():
                        accept_risk(finding, reason)
                        st.rerun()
                    else:
                        st.warning("Qəbul üçün səbəb daxil edin.")


# ---------- Sidebar ----------
with st.sidebar:
    st.header("🛡️ Azure Scanner")
    st.caption("Storage, NSG, Key Vault və asılılıqlar (CVE) üzrə yoxlama")

    if st.button("🔄 Yeni skan başlat", type="primary", width="stretch"):
        with st.spinner("Azure resursları skan edilir..."):
            try:
                run_scan()
                st.success("Skan tamamlandı!")
                st.rerun()
            except EnvironmentError as e:
                # Konfiqurasiya xetasi - metn bizim yazdigimizdir, sistem
                # detali sizdirmir ve istifadeci onu ozu duzeltmelidir
                st.error(str(e))
            except Exception:
                # Azure SDK xetalari resurs ID-si, tenant, endpoint kimi
                # detallar ehtiva ede biler - onlari brauzere deyil, yalniz
                # server log-una yaziriq
                logging.exception("Skan zamanı gözlənilməz xəta")
                st.error(
                    "Skan zamanı xəta baş verdi. Texniki detallar serverin "
                    "log-una yazıldı."
                )

    st.divider()

    scan_files = list_scan_files()
    st.subheader("Skan tarixçəsi")
    st.caption(f"Ümumi skan sayı: {len(scan_files)}")

    if scan_files:
        display_names = [f.name for f in reversed(scan_files)]
        selected_name = st.selectbox("Baxılacaq skan", display_names, key="selected_scan")

        col_del, col_clear = st.columns(2)
        with col_del:
            if st.button("🗑️ Bunu sil", width="stretch"):
                selected_path = next(f for f in scan_files if f.name == selected_name)
                delete_scan(selected_path)
                st.rerun()
        with col_clear:
            if st.button("🧹 Hamısını təmizlə", width="stretch"):
                clear_history()
                st.rerun()
    else:
        selected_name = None

    render_logout()


# ---------- Ana səhifə ----------
st.title("Azure Misconfiguration Scanner")

scan_files = list_scan_files()
if not scan_files:
    st.info("Hələ heç bir skan aparılmayıb. Sol paneldən 'Yeni skan başlat' düyməsini basın.")
    st.stop()

selected_path = next(
    (f for f in scan_files if f.name == selected_name),
    scan_files[-1],
)
latest = load_scan(selected_path)

accepted = accepted_keys_set()
scores = calculate_scores(latest["findings"], accepted_keys=accepted)
scan_time = datetime.fromisoformat(latest["scan_time"]).strftime("%Y-%m-%d %H:%M UTC")

# Kohne skan fayllarinda tek "subscription_id", yenilerde "subscription_ids" var
subscription_ids = latest.get("subscription_ids") or [latest.get("subscription_id", "—")]
subscription_label = ", ".join(subscription_ids)

st.caption(f"Son skan: {scan_time} | Subscription: {subscription_label}")

azure_findings = [f for f in latest["findings"] if f["category"] != "Dependency"]
dependency_findings = [f for f in latest["findings"] if f["category"] == "Dependency"]

tab_overview, tab_findings, tab_history, tab_deps, tab_accepted = st.tabs(
    ["📊 Overview", "🔍 Findings", "📂 History", "📦 Dependencies", "✅ Accepted Risks"]
)

# ---------- Tab: Overview ----------
with tab_overview:
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(f"{_score_color(scores['overall'])} Ümumi Posture Score", f"{scores['overall']}/100")
    with col2:
        st.metric("🔴 High", scores["findings_by_severity"]["High"])
    with col3:
        st.metric("🟡 Medium", scores["findings_by_severity"]["Medium"])
    with col4:
        st.metric("🟢 Low", scores["findings_by_severity"]["Low"])

    st.divider()

    st.subheader("Kateqoriya üzrə vəziyyət")
    cat_cols = st.columns(len(scores["by_category"]))
    for col, (category, cat_score) in zip(cat_cols, scores["by_category"].items()):
        with col:
            st.metric(f"{_score_color(cat_score)} {category}", f"{cat_score}/100")

    st.divider()

    st.subheader("Son iki skan arasında dəyişiklik")
    diff = compare_last_two_scans()

    if diff is None:
        st.caption("Müqayisə üçün ən azı 2 skan lazımdır.")
    else:
        change = diff["score_change"]
        change_label = f"+{change}" if change > 0 else str(change)
        st.metric("Score dəyişimi", f"{diff['previous_score']} → {diff['latest_score']}", change_label)

        dc1, dc2 = st.columns(2)
        with dc1:
            st.markdown(f"**🆕 Yeni tapıntılar ({len(diff['new_findings'])})**")
            for f in diff["new_findings"]:
                st.markdown(f"- `{f['resource']}` — {f['issue']}")
        with dc2:
            st.markdown(f"**✅ Həll olunanlar ({len(diff['resolved_findings'])})**")
            for f in diff["resolved_findings"]:
                st.markdown(f"- `{f['resource']}` — {f['issue']}")

    history = score_history()
    if len(history) > 1:
        st.divider()
        st.subheader("Score trendi")
        history_df = pd.DataFrame(history)
        history_df["time"] = pd.to_datetime(history_df["time"])
        st.line_chart(history_df.set_index("time")["score"])

# ---------- Tab: Findings (Azure check-ləri) ----------
with tab_findings:
    st.subheader("Tapıntılar")
    if azure_findings:
        df = pd.DataFrame(azure_findings)
        df["status"] = df.apply(
            lambda r: "✅ Qəbul edilib" if (r["category"], r["resource"], r["check"]) in accepted else "",
            axis=1,
        )
        df["_sort"] = df["severity"].map(SEVERITY_ORDER)
        df = df.sort_values("_sort").drop(columns="_sort")

        st.dataframe(
            df.style.apply(_row_style, axis=1),
            width="stretch",
            hide_index=True,
        )

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 CSV kimi yüklə", csv, "azure_scan_findings.csv", "text/csv")

        st.markdown("**🛠️ Remediation təklifləri və risk qəbulu**")
        _remediation_and_acceptance_section(azure_findings, accepted, allow_accept=True)
    else:
        st.success("Heç bir Azure konfiqurasiya problemi tapılmadı! 🎉")

# ---------- Tab: History ----------
with tab_history:
    st.subheader("Bütün skanlar")
    rows = []
    for path in scan_files:
        scan = load_scan(path)
        rows.append({
            "fayl": path.name,
            "vaxt (UTC)": datetime.fromisoformat(scan["scan_time"]).strftime("%Y-%m-%d %H:%M"),
            "tapıntı sayı": scan["total_findings"],
            "score": calculate_scores(scan["findings"])["overall"],
        })
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    st.caption("Skan seçmə/silmə/təmizləmə əməliyyatları sol paneldəki 'Skan tarixçəsi' bölməsindədir.")

# ---------- Tab: Dependencies ----------
with tab_deps:
    st.subheader("📦 Dependency (PyPI) tapıntıları")
    if dependency_findings:
        df_dep = pd.DataFrame(dependency_findings)
        df_dep["_sort"] = df_dep["severity"].map(SEVERITY_ORDER)
        df_dep = df_dep.sort_values("_sort").drop(columns="_sort")

        st.dataframe(
            df_dep.style.apply(_severity_style, axis=1),
            width="stretch",
            hide_index=True,
        )

        csv_dep = df_dep.to_csv(index=False).encode("utf-8")
        st.download_button("📥 CSV kimi yüklə", csv_dep, "dependency_findings.csv", "text/csv", key="dep_csv")

        st.markdown("**🛠️ Remediation təklifləri**")
        _remediation_and_acceptance_section(dependency_findings, accepted, allow_accept=False)
    else:
        st.caption(
            "Dependency tapıntısı yoxdur - `requirements.lock.txt` yoxdur, ya da "
            "OSV.dev-də bilinən CVE tapılmadı."
        )

# ---------- Tab: Accepted Risks ----------
with tab_accepted:
    st.subheader("✅ Qəbul edilmiş risklər")
    accepted_risks = list_accepted_risks()
    if accepted_risks:
        st.dataframe(pd.DataFrame(accepted_risks), width="stretch", hide_index=True)
    else:
        st.caption("Hələ heç bir risk qəbul edilməyib.")
