"""
Streamlit dashboard for AI attack surface findings.
"""

from pathlib import Path

import pandas as pd
import streamlit as st


FINDINGS_FILE = Path("findings.csv")
RISK_ORDER = ["Critical", "High", "Medium", "Low"]
DEFAULT_COLUMNS = {
    "risk": "Unknown",
    "risk_score": 0,
    "asset_name": "unknown-asset",
    "detected_service": "Unknown",
    "attack_path": "Discovery source -> Unclassified AI exposure -> Manual review",
    "discovery_source": "unknown",
    "source": "unknown",
    "service_classification": "Unknown",
    "attack_surface_classification": "Unclassified Exposure",
    "exposure_category": "Unclassified Exposure",
    "image": "",
    "endpoint": "",
    "status": "",
    "http_status": "",
    "server_header": "",
    "page_title": "",
    "issue": "Finding is missing issue context.",
    "recommendation": "Review the asset manually and update scanner output if needed.",
    "mitre_atlas_tactic": "Unknown",
    "mitre_atlas_technique": "Unknown",
    "cloud_provider": "",
    "region": "",
    "subnet": "",
    "gpu_enabled": "false",
    "public_exposure": "false",
    "ai_provider": "",
    "provider_type": "",
    "outbound_ai_traffic": "false",
    "telemetry_source": "",
}


st.set_page_config(page_title="AI Surface Scanner", layout="wide")

st.title("AI Attack Surface Discovery")
st.caption("Enterprise AI workload visibility, exposure analysis, and attack path review")


@st.cache_data
def load_findings(path):
    try:
        return pd.read_csv(path)
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return pd.DataFrame()


def normalize_findings(dataframe):
    """Add safe defaults so incomplete scanner outputs do not break the dashboard."""
    normalized = dataframe.copy()

    for column, default_value in DEFAULT_COLUMNS.items():
        if column not in normalized.columns:
            normalized[column] = default_value

    normalized["risk"] = normalized["risk"].fillna("Unknown").replace("", "Unknown")
    normalized["risk_score"] = pd.to_numeric(normalized["risk_score"], errors="coerce").fillna(0)
    normalized["asset_name"] = normalized["asset_name"].fillna("unknown-asset").replace("", "unknown-asset")
    normalized["detected_service"] = (
        normalized["detected_service"].fillna("Unknown").replace("", "Unknown")
    )
    normalized["gpu_enabled"] = normalized["gpu_enabled"].fillna("false").astype(str).str.lower()
    normalized["public_exposure"] = normalized["public_exposure"].fillna("false").astype(str).str.lower()
    normalized["outbound_ai_traffic"] = (
        normalized["outbound_ai_traffic"].fillna("false").astype(str).str.lower()
    )

    missing_attack_path = normalized["attack_path"].isna() | (normalized["attack_path"] == "")
    normalized.loc[missing_attack_path, "attack_path"] = (
        "Discovery source -> "
        + normalized.loc[missing_attack_path, "exposure_category"].astype(str)
        + " -> "
        + normalized.loc[missing_attack_path, "service_classification"].astype(str)
        + " -> Manual review"
    )

    return normalized


def available_columns(dataframe, columns):
    return [column for column in columns if column in dataframe.columns]


def sort_by_risk_score(dataframe):
    """Sort by risk_score even when a partial dataframe is missing the column."""
    sortable = dataframe.copy()

    if "risk_score" not in sortable.columns:
        sortable["risk_score"] = 0

    sortable["risk_score"] = pd.to_numeric(sortable["risk_score"], errors="coerce").fillna(0)
    return sortable.sort_values("risk_score", ascending=False)


def truthy_count(series):
    """Count true-like values in a defensive way."""
    return series.astype(str).str.lower().isin(["true", "yes", "1"]).sum()


if not FINDINGS_FILE.exists():
    st.warning("findings.csv was not found. Run `python scanner.py` first.")
    st.stop()


findings = normalize_findings(load_findings(FINDINGS_FILE))

if findings.empty:
    st.info("No AI-related services were detected in the latest scan.")
    st.stop()


total_findings = len(findings)
critical_count = len(findings[findings["risk"] == "Critical"])
high_count = len(findings[findings["risk"] == "High"])
service_count = findings["detected_service"].nunique()
avg_risk = round(findings["risk_score"].mean(), 1)
source_count = findings["discovery_source"].nunique()
gpu_count = truthy_count(findings["gpu_enabled"])
public_count = truthy_count(findings["public_exposure"])
outbound_ai_count = truthy_count(findings["outbound_ai_traffic"])

metric_1, metric_2, metric_3, metric_4, metric_5, metric_6 = st.columns(6)
metric_1.metric("Findings", total_findings)
metric_2.metric("Critical", critical_count)
metric_3.metric("High", high_count)
metric_4.metric("AI Services", service_count)
metric_5.metric("Avg Score", avg_risk)
metric_6.metric("Sources", source_count)

cloud_metric_1, cloud_metric_2, cloud_metric_3 = st.columns(3)
cloud_metric_1.metric("GPU Workloads", gpu_count)
cloud_metric_2.metric("Public Cloud Assets", public_count)
cloud_metric_3.metric("Outbound AI Traffic", outbound_ai_count)

st.divider()

left_column, middle_column, right_column = st.columns(3)

with left_column:
    st.subheader("Risk Severity")
    risk_counts = findings["risk"].value_counts().reindex(RISK_ORDER, fill_value=0)
    st.bar_chart(risk_counts)

with middle_column:
    st.subheader("Service Breakdown")
    st.bar_chart(findings["detected_service"].value_counts())

with right_column:
    st.subheader("Exposure Categories")
    st.bar_chart(findings["exposure_category"].value_counts())

left_column, middle_column, right_column = st.columns(3)

with left_column:
    st.subheader("Cloud Regions")
    region_counts = findings[findings["region"] != ""]["region"].value_counts()
    if region_counts.empty:
        st.info("No cloud region data available.")
    else:
        st.bar_chart(region_counts)

with middle_column:
    st.subheader("AI Provider Communication")
    provider_counts = findings[findings["ai_provider"] != ""]["ai_provider"].value_counts()
    if provider_counts.empty:
        st.info("No outbound AI provider traffic detected.")
    else:
        st.bar_chart(provider_counts)

with right_column:
    st.subheader("Telemetry Sources")
    telemetry_counts = findings[findings["telemetry_source"] != ""]["telemetry_source"].value_counts()
    if telemetry_counts.empty:
        st.info("No cloud telemetry source data available.")
    else:
        st.bar_chart(telemetry_counts)


left_column, right_column = st.columns(2)

with left_column:
    st.subheader("Discovery Sources")
    st.dataframe(
        findings["discovery_source"].value_counts().rename_axis("source").reset_index(name="findings"),
        hide_index=True,
        width="stretch",
    )

with right_column:
    st.subheader("Attack Surface Classification")
    st.dataframe(
        findings["attack_surface_classification"]
        .value_counts()
        .rename_axis("classification")
        .reset_index(name="findings"),
        hide_index=True,
        width="stretch",
    )


st.subheader("AI Asset Inventory")
inventory_columns = available_columns(
    findings,
    [
        "asset_name",
        "source",
        "discovery_source",
        "detected_service",
        "service_classification",
        "attack_surface_classification",
        "image",
        "endpoint",
        "status",
        "cloud_provider",
        "region",
        "subnet",
        "gpu_enabled",
        "public_exposure",
    ],
)

st.dataframe(
    findings[inventory_columns].drop_duplicates(),
    hide_index=True,
    width="stretch",
    column_config={
        "asset_name": st.column_config.TextColumn("Asset"),
        "source": st.column_config.TextColumn("Source"),
        "discovery_source": st.column_config.TextColumn("Discovery Source"),
        "detected_service": st.column_config.TextColumn("Service"),
        "service_classification": st.column_config.TextColumn("Service Class"),
        "attack_surface_classification": st.column_config.TextColumn("Attack Surface"),
        "image": st.column_config.TextColumn("Image"),
        "endpoint": st.column_config.TextColumn("Endpoint"),
        "status": st.column_config.TextColumn("Status"),
        "cloud_provider": st.column_config.TextColumn("Cloud"),
        "region": st.column_config.TextColumn("Region"),
        "subnet": st.column_config.TextColumn("Subnet"),
        "gpu_enabled": st.column_config.TextColumn("GPU"),
        "public_exposure": st.column_config.TextColumn("Public"),
    },
)

st.subheader("Cloud Telemetry Findings")
telemetry_findings = findings[
    (findings["telemetry_source"] != "") | (findings["outbound_ai_traffic"] == "true")
]

telemetry_columns = available_columns(
    telemetry_findings,
    [
        "risk",
        "asset_name",
        "ai_provider",
        "provider_type",
        "outbound_ai_traffic",
        "telemetry_source",
        "endpoint",
        "evidence",
        "recommendation",
    ],
)

if telemetry_findings.empty:
    st.info("No cloud telemetry findings available. Run `python scanner.py --cloud-logs`.")
else:
    st.dataframe(
        sort_by_risk_score(telemetry_findings)[telemetry_columns],
        hide_index=True,
        width="stretch",
    )


st.subheader("Attack Path Visualization")
attack_paths = sort_by_risk_score(findings)[
    ["risk", "risk_score", "asset_name", "detected_service", "attack_path"]
]

for _, row in attack_paths.head(5).iterrows():
    st.markdown(
        f"**{row['risk']} - {row['asset_name']} ({row['detected_service']})**  \n"
        f"`{row['attack_path']}`"
    )


st.subheader("AI-Specific Exposure Findings")
finding_columns = available_columns(
    findings,
    [
        "risk",
        "risk_score",
        "detected_service",
        "service_classification",
        "attack_surface_classification",
        "exposure_category",
        "source",
        "discovery_source",
        "asset_name",
        "endpoint",
        "http_status",
        "server_header",
        "page_title",
        "cloud_provider",
        "region",
        "subnet",
        "gpu_enabled",
        "public_exposure",
        "ai_provider",
        "outbound_ai_traffic",
        "telemetry_source",
        "issue",
        "recommendation",
        "mitre_atlas_tactic",
        "mitre_atlas_technique",
    ],
)

st.dataframe(
    sort_by_risk_score(findings)[finding_columns],
    hide_index=True,
    width="stretch",
    column_config={
        "risk": st.column_config.TextColumn("Risk"),
        "risk_score": st.column_config.NumberColumn("Score"),
        "detected_service": st.column_config.TextColumn("Service"),
        "service_classification": st.column_config.TextColumn("Service Class"),
        "attack_surface_classification": st.column_config.TextColumn("Attack Surface"),
        "exposure_category": st.column_config.TextColumn("Exposure"),
        "source": st.column_config.TextColumn("Source"),
        "discovery_source": st.column_config.TextColumn("Discovery Source"),
        "asset_name": st.column_config.TextColumn("Asset"),
        "endpoint": st.column_config.TextColumn("Endpoint"),
        "http_status": st.column_config.NumberColumn("HTTP"),
        "server_header": st.column_config.TextColumn("Server"),
        "page_title": st.column_config.TextColumn("Page Title"),
        "cloud_provider": st.column_config.TextColumn("Cloud"),
        "region": st.column_config.TextColumn("Region"),
        "subnet": st.column_config.TextColumn("Subnet"),
        "gpu_enabled": st.column_config.TextColumn("GPU"),
        "public_exposure": st.column_config.TextColumn("Public"),
        "ai_provider": st.column_config.TextColumn("AI Provider"),
        "outbound_ai_traffic": st.column_config.TextColumn("Outbound AI"),
        "telemetry_source": st.column_config.TextColumn("Telemetry"),
        "issue": st.column_config.TextColumn("Issue"),
        "recommendation": st.column_config.TextColumn("Recommendation"),
        "mitre_atlas_tactic": st.column_config.TextColumn("ATLAS Tactic"),
        "mitre_atlas_technique": st.column_config.TextColumn("ATLAS Technique"),
    },
)
