"""Streamlit dashboard for the synthetic IAM governance dataset."""
from pathlib import Path
from datetime import date
import pandas as pd
import streamlit as st

from identityguard.config import RiskPolicy, WEIGHTS
from identityguard.data import DataValidationError, load_data
from identityguard.scoring import analyze

st.set_page_config(page_title="IdentityGuard | IAM Analytics", page_icon="🛡️", layout="wide")
st.title("🛡️ IdentityGuard")
st.caption("Identity Governance & Risk Analytics | Demonstration using fictional identities")
st.info("Demo only. Scores indicate review priority, not verified compromises or automated enforcement.")

with st.sidebar:
    st.header("Audit settings")
    data_dir = st.text_input("CSV data folder", "data")
    as_of = st.date_input("Audit as of", value=date.today())
    inactive = st.slider("Dormant identity threshold (days)", 60, 180, 90)
    stale = st.slider("Stale identity threshold (days)", 15, 60, 45, disabled=inactive <= 60)
    failed_threshold = st.slider("Failed sign-in threshold", 3, 12, 5)
    st.caption("Edit thresholds to explore how policies change the findings.")

policy = RiskPolicy(inactive_days=inactive, stale_days=min(stale, inactive - 1),
                    failed_login_threshold=failed_threshold)

@st.cache_data(show_spinner=False)
def cached_load(folder: str, file_stamps: tuple):
    return load_data(folder)

try:
    folder = Path(data_dir)
    stamps = tuple((p.name, p.stat().st_mtime_ns) for p in
                   [folder / f"{name}.csv" for name in ("users", "roles", "assignments", "signins")])
    data = cached_load(str(folder), stamps)
    scored, findings = analyze(data, as_of=as_of, policy=policy)
except (DataValidationError, OSError, ValueError) as exc:
    st.error(f"Cannot load or analyze data: {exc}")
    st.code("python -m identityguard.cli generate --data-dir data")
    st.stop()

with st.sidebar:
    st.divider()
    department = st.multiselect("Department", sorted(scored["department"].unique()))
    risk = st.multiselect("Risk level", ["High", "Medium", "Low"])
    enabled_only = st.checkbox("Enabled identities only")

filtered = scored.copy()
if department:
    filtered = filtered[filtered["department"].isin(department)]
if risk:
    filtered = filtered[filtered["risk_level"].isin(risk)]
if enabled_only:
    filtered = filtered[filtered["enabled"]]
visible_findings = findings[findings["user_id"].isin(filtered["user_id"])]

m1, m2, m3, m4 = st.columns(4)
m1.metric("Identities in view", f"{len(filtered):,}")
m2.metric("High risk", f"{(filtered['risk_level'] == 'High').sum():,}")
m3.metric("Privileged identities", f"{filtered['privileged'].sum():,}")
m4.metric("Policy findings", f"{len(visible_findings):,}")

overview, accounts, audit, rules = st.tabs(["Overview", "Identity Explorer", "Audit Findings", "Scoring Rules"])
with overview:
    left, right = st.columns(2)
    with left:
        st.subheader("Risk distribution")
        counts = filtered["risk_level"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0)
        st.bar_chart(counts.rename("Identities"))
    with right:
        st.subheader("Findings by rule")
        if visible_findings.empty:
            st.write("No findings match the current filters.")
        else:
            st.bar_chart(visible_findings["rule"].value_counts().rename("Findings"))
    st.subheader("Risk by department")
    st.dataframe(filtered.groupby("department", as_index=False).agg(
        identities=("user_id", "size"), average_risk=("risk_score", "mean"),
        high_risk=("risk_level", lambda x: (x == "High").sum())
    ).round(1), use_container_width=True, hide_index=True)
with accounts:
    st.subheader("User access risk")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button("Download filtered user risks CSV", filtered.to_csv(index=False).encode(),
                       "identityguard_user_risks.csv", "text/csv")
    selected = st.selectbox("Inspect an identity", [""] + filtered["user_id"].tolist())
    if selected:
        record = scored.loc[scored["user_id"] == selected].iloc[0]
        st.write(f"**{record['name']}** | {record['department']} | Score: {record['risk_score']}/100")
        assigned = data["assignments"].query("user_id == @selected").merge(data["roles"], on="role_id")
        st.write("Assigned roles")
        st.dataframe(assigned[["role_id", "role_name", "privileged"]], hide_index=True)
        st.write("Detected policy findings")
        st.dataframe(findings[findings["user_id"] == selected], hide_index=True)
with audit:
    st.subheader("Audit-ready review queue")
    st.caption("Suggestions require an authorized human reviewer before any access changes.")
    st.dataframe(visible_findings, use_container_width=True, hide_index=True)
    st.download_button("Download filtered findings CSV", visible_findings.to_csv(index=False).encode(),
                       "identityguard_audit_findings.csv", "text/csv")
with rules:
    st.subheader("Explainable rules and point weights")
    st.dataframe(pd.DataFrame([{"rule": k, "points": v} for k, v in WEIGHTS.items()]), hide_index=True)
    st.markdown("**Scoring:** add weights for each triggered rule, then cap at 100. High ≥60, Medium ≥30, Low <30.")
    st.markdown("**Assumptions:** DE is the expected sign-in country. Geolocation alone is weak evidence. "
                "Disabled users are not flagged for stale access or role conflicts. "
                "This demo does not verify MFA strength, real account compromise, or entitlement necessity.")
    st.markdown("**Data:** All accounts, names, roles, and authentication events are fictional. "
                "No tenant credentials or real employee records are required.")
