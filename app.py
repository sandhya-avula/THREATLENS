import io
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

APP_NAME = "ThreatLens"
DEFAULT_LOG = Path(__file__).parent / "data" / "threatlens_sample_logs.csv"



st.set_page_config(
    page_title="ThreatLens | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

    
st.markdown("""
<style>
.stApp {
    background-color: #080d18;
    color: #e6edf7;
}

[data-testid="stSidebar"] {
    background-color: #0d1525;
    border-right: 1px solid #23334d;
}

h1, h2, h3 {
    color: #42e8f5 !important;
}

[data-testid="stMetric"] {
    background: linear-gradient(135deg, #111c30, #0b1220);
    border: 1px solid #243b58;
    padding: 18px;
    border-radius: 12px;
}

[data-testid="stMetricValue"] {
    color: #42e8f5;
}

.stButton > button {
    background-color: #10263b;
    color: #42e8f5;
    border: 1px solid #42e8f5;
    border-radius: 8px;
}

.stButton > button:hover {
    background-color: #183b52;
    color: white;
    border-color: #42e8f5;
}

[data-testid="stDataFrame"] {
    border: 1px solid #243b58;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)




st.markdown("""
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
div[data-testid="stMetric"] {border: 1px solid #26364a; padding: 14px; border-radius: 12px;}
.small-muted {color: #8b98a9;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ ThreatLens")
st.caption("Security Log Analysis & Incident Investigation Platform")
st.markdown("Analyze authentication logs, surface suspicious patterns, and organize your investigation.")

@st.cache_data
def load_sample():
    return pd.read_csv(DEFAULT_LOG)

def normalize_columns(df):
    df = df.copy()
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    aliases = {
        "timestamp": "event_time", "time": "event_time", "date": "event_time",
        "ip": "source_ip", "src_ip": "source_ip", "ip_address": "source_ip",
        "user": "username", "account": "username",
        "event": "event_type", "action": "event_type",
        "result": "status", "outcome": "status"
    }
    df = df.rename(columns={c: aliases.get(c, c) for c in df.columns})
    return df

uploaded = st.sidebar.file_uploader("Upload a security log CSV", type=["csv"])
if uploaded is not None:
    try:
        df = normalize_columns(pd.read_csv(uploaded))
        data_source = f"Uploaded: {uploaded.name}"
    except Exception as exc:
        st.error(f"Could not read that CSV: {exc}")
        st.stop()
else:
    df = normalize_columns(load_sample())
    data_source = "Built-in synthetic demo logs"

required = {"event_time", "source_ip", "username", "event_type", "status"}
missing = required - set(df.columns)
if missing:
    st.error("The CSV is missing required columns: " + ", ".join(sorted(missing)))
    st.info("Required columns: event_time, source_ip, username, event_type, status")
    st.stop()

df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
for col in ["source_ip", "username", "event_type", "status"]:
    df[col] = df[col].fillna("unknown").astype(str)
df = df.dropna(subset=["event_time"]).sort_values("event_time")
df["status_norm"] = df["status"].str.lower().str.strip()
df["event_norm"] = df["event_type"].str.lower().str.strip()

failed = df[df["status_norm"].isin(["failed", "failure", "denied", "invalid"])]
success = df[df["status_norm"].isin(["success", "successful", "accepted", "ok"])]

# Lightweight, explainable detection rules for authentication logs.
alerts = []
for ip, group in failed.groupby("source_ip"):
    if len(group) >= 5:
        alerts.append({"severity": "High", "rule": "Repeated failed logins", "source_ip": ip,
                       "details": f"{len(group)} failed attempts observed", "events": len(group)})
for ip, group in df.groupby("source_ip"):
    accounts = group["username"].nunique()
    if accounts >= 3:
        alerts.append({"severity": "Medium", "rule": "One IP touching multiple accounts", "source_ip": ip,
                       "details": f"Activity involving {accounts} distinct usernames", "events": len(group)})
for ip, group in df.groupby("source_ip"):
    g = group.sort_values("event_time")
    statuses = g["status_norm"].tolist()
    if any(statuses[i] in ["success", "successful", "accepted", "ok"] and
           any(s in ["failed", "failure", "denied", "invalid"] for s in statuses[max(0, i-5):i])
           for i in range(len(statuses))):
        alerts.append({"severity": "High", "rule": "Success after recent failures", "source_ip": ip,
                       "details": "A successful login followed failed attempts from this IP", "events": len(group)})

alerts_df = pd.DataFrame(alerts, columns=["severity", "rule", "source_ip", "details", "events"])
if not alerts_df.empty:
    alerts_df = alerts_df.drop_duplicates(subset=["severity", "rule", "source_ip"])

st.sidebar.markdown("---")
st.sidebar.write(f"**Data source:** {data_source}")
st.sidebar.caption("Use only logs you are authorized to analyze. Demo data is synthetic.")

total_events = len(df)
unique_ips = df["source_ip"].nunique()
high_alerts = int((alerts_df["severity"] == "High").sum()) if not alerts_df.empty else 0
m1, m2, m3, m4 = st.columns(4)
m1.metric("Events analyzed", f"{total_events:,}")
m2.metric("Unique source IPs", f"{unique_ips:,}")
m3.metric("Failed logins", f"{len(failed):,}")
m4.metric("High-severity alerts", f"{high_alerts:,}")

tab_overview, tab_alerts, tab_events, tab_case = st.tabs(
    ["📊 Overview", "🚨 Detection alerts", "🔎 Event explorer", "🗂️ Investigation notes"]
)

with tab_overview:
    left, right = st.columns(2)
    with left:
        st.subheader("Events over time")
        if not df.empty:
            timeline = df.set_index("event_time").resample("1h").size().rename("events").reset_index()
            st.plotly_chart(px.line(timeline, x="event_time", y="events", markers=True,
                                    title="Events per hour"), use_container_width=True)
        else:
            st.info("No valid events to chart.")
    with right:
        st.subheader("Event outcomes")
        outcomes = df["status"].value_counts().rename_axis("status").reset_index(name="count")
        st.plotly_chart(px.pie(outcomes, names="status", values="count", hole=0.45,
                               title="Status distribution"), use_container_width=True)
    st.subheader("Most active source IPs")
    ip_counts = df["source_ip"].value_counts().head(10).rename_axis("source_ip").reset_index(name="events")
    st.plotly_chart(px.bar(ip_counts, x="source_ip", y="events", title="Top 10 source IPs"),
                    use_container_width=True)

with tab_alerts:
    st.subheader("Explainable detection results")
    st.caption("These are heuristic indicators for investigation, not proof that an attack occurred.")
    if alerts_df.empty:
        st.success("No alerts triggered by the current rules.")
    else:
        severity_filter = st.multiselect("Severity", ["High", "Medium"], default=["High", "Medium"])
        visible_alerts = alerts_df[alerts_df["severity"].isin(severity_filter)]
        st.dataframe(visible_alerts, use_container_width=True, hide_index=True)
        st.download_button("Download alerts CSV", visible_alerts.to_csv(index=False).encode("utf-8"),
                           "threatlens_alerts.csv", "text/csv")

with tab_events:
    st.subheader("Search and filter events")
    c1, c2, c3 = st.columns(3)
    with c1:
        ip_options = sorted(df["source_ip"].unique().tolist())
        selected_ips = st.multiselect("Source IP", ip_options)
    with c2:
        status_options = sorted(df["status"].unique().tolist())
        selected_status = st.multiselect("Status", status_options)
    with c3:
        search_text = st.text_input("Search username or event type")
    filtered = df.copy()
    if selected_ips:
        filtered = filtered[filtered["source_ip"].isin(selected_ips)]
    if selected_status:
        filtered = filtered[filtered["status"].isin(selected_status)]
    if search_text:
        mask = filtered["username"].str.contains(search_text, case=False, na=False) | \
               filtered["event_type"].str.contains(search_text, case=False, na=False)
        filtered = filtered[mask]
    display_cols = [c for c in ["event_time", "source_ip", "username", "event_type", "status"] if c in filtered.columns]
    st.caption(f"Showing {len(filtered):,} of {len(df):,} events")
    st.dataframe(filtered[display_cols], use_container_width=True, hide_index=True)
    st.download_button("Export filtered events CSV", filtered[display_cols].to_csv(index=False).encode("utf-8"),
                       "threatlens_filtered_events.csv", "text/csv")

with tab_case:
    st.subheader("Investigation workspace")
    st.warning("Notes and status are held only for this running session; they are not saved permanently.")
    alert_options = ["General investigation"] + (
        [f"{row['severity']} | {row['rule']} | {row['source_ip']}" for _, row in alerts_df.iterrows()]
        if not alerts_df.empty else []
    )
    selected_case = st.selectbox("Investigation / alert", alert_options)
    if "case_notes" not in st.session_state:
        st.session_state.case_notes = {}
    if "case_status" not in st.session_state:
        st.session_state.case_status = {}
    st.session_state.case_status[selected_case] = st.selectbox(
        "Case status", ["New", "Investigating", "Escalated", "Closed"],
        index=["New", "Investigating", "Escalated", "Closed"].index(
            st.session_state.case_status.get(selected_case, "New")
        ), key="status_" + str(alert_options.index(selected_case))
    )
    st.session_state.case_notes[selected_case] = st.text_area(
        "Analyst notes", value=st.session_state.case_notes.get(selected_case, ""),
        placeholder="Record what you observed, evidence to verify, and next investigation steps.",
        height=150, key="notes_" + str(alert_options.index(selected_case))
    )
    if st.button("Prepare case summary CSV"):
        case_summary = pd.DataFrame([{
            "case": selected_case,
            "status": st.session_state.case_status.get(selected_case, "New"),
            "notes": st.session_state.case_notes.get(selected_case, "")
        }])
        st.download_button("Download case summary", case_summary.to_csv(index=False).encode("utf-8"),
                           "threatlens_case_summary.csv", "text/csv")

st.markdown("---")
st.caption("ThreatLens • Portfolio demo • Detection findings require analyst validation.")
