"""
Mock cloud telemetry analysis for AI provider communication.

This module simulates activity logs, flow logs, DNS logs, and outbound
connections. It detects traffic to common AI providers without requiring any
cloud credentials.
"""


AI_PROVIDER_DOMAINS = {
    "api.openai.com": {"provider": "OpenAI", "provider_type": "LLM API Provider"},
    "anthropic.com": {"provider": "Anthropic", "provider_type": "LLM API Provider"},
    "huggingface.co": {"provider": "HuggingFace", "provider_type": "Model Hub and Inference Provider"},
    "replicate.com": {"provider": "Replicate", "provider_type": "Hosted Model Inference Provider"},
    "cohere.ai": {"provider": "Cohere", "provider_type": "LLM API Provider"},
}


def generate_mock_cloud_logs():
    """Return simulated cloud telemetry events."""
    return [
        {
            "telemetry_source": "dns_logs",
            "asset_name": "gpu-inference-public-01",
            "destination_domain": "api.openai.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 18420,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "gpu-inference-public-01",
            "destination_domain": "replicate.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 22800,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "research-notebook-02",
            "destination_domain": "huggingface.co",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 93210,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "research-notebook-02",
            "destination_domain": "api.openai.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 34120,
        },
        {
            "telemetry_source": "activity_logs",
            "asset_name": "research-notebook-public-03",
            "destination_domain": "api.openai.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 88200,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "research-notebook-public-03",
            "destination_domain": "huggingface.co",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 62100,
        },
        {
            "telemetry_source": "activity_logs",
            "asset_name": "genai-demo-web-01",
            "destination_domain": "anthropic.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 42100,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "genai-demo-web-01",
            "destination_domain": "replicate.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 19820,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "internal-streamlit-app-01",
            "destination_domain": "cohere.ai",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 15200,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "internal-streamlit-app-01",
            "destination_domain": "api.openai.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 20110,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "tgi-inference-public-01",
            "destination_domain": "huggingface.co",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 156800,
        },
        {
            "telemetry_source": "activity_logs",
            "asset_name": "tgi-inference-public-01",
            "destination_domain": "replicate.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 48100,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "triton-serving-private-01",
            "destination_domain": "api.openai.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 11200,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "triton-serving-private-01",
            "destination_domain": "anthropic.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 17400,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "batch-worker-03",
            "destination_domain": "updates.example.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 2400,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "rag-vector-cache-01",
            "destination_domain": "cohere.ai",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 15700,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "rag-vector-cache-01",
            "destination_domain": "huggingface.co",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 27700,
        },
        {
            "telemetry_source": "activity_logs",
            "asset_name": "mlflow-tracking-01",
            "destination_domain": "huggingface.co",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 71400,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "mlflow-tracking-01",
            "destination_domain": "replicate.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 9100,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "open-webui-public-01",
            "destination_domain": "api.openai.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 132900,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "open-webui-public-01",
            "destination_domain": "anthropic.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 48900,
        },
        {
            "telemetry_source": "flow_logs",
            "asset_name": "gpu-training-private-01",
            "destination_domain": "cohere.ai",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 24800,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "gpu-training-private-01",
            "destination_domain": "huggingface.co",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 209400,
        },
        {
            "telemetry_source": "dns_logs",
            "asset_name": "security-scanner-01",
            "destination_domain": "packages.example.com",
            "destination_port": 443,
            "action": "allowed",
            "bytes_out": 3900,
        },
    ]


def detect_ai_provider(domain):
    """Classify a domain as an AI provider when it matches known providers."""
    normalized_domain = (domain or "").lower()

    for provider_domain, metadata in AI_PROVIDER_DOMAINS.items():
        if provider_domain in normalized_domain:
            return metadata

    return {"provider": "", "provider_type": ""}


def analyze_ai_provider_traffic(log_events=None):
    """Return only telemetry events that show outbound AI provider traffic."""
    events = log_events or generate_mock_cloud_logs()
    detections = []

    for event in events:
        provider_metadata = detect_ai_provider(event.get("destination_domain", ""))

        if not provider_metadata["provider"]:
            continue

        enriched_event = event.copy()
        enriched_event.update(provider_metadata)
        detections.append(enriched_event)

    return detections
