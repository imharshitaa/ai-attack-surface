"""
AI Attack Surface Discovery and Exposure Scanner.

Discovers AI-related Docker containers, optional Kubernetes pods, common AI HTTP
services, and known AI/vector database ports. Findings are written to
findings.csv for review in the Streamlit dashboard.
"""

import argparse
import csv
import logging
import re
from pathlib import Path

from cloud_discovery import discover_cloud_assets, summarize_asset
from cloud_logs import analyze_ai_provider_traffic

try:
    import requests
except ImportError:
    requests = None

try:
    import docker
except ImportError:
    docker = None

try:
    import nmap
except ImportError:
    nmap = None


FINDINGS_FILE = Path("findings.csv")
LOG_FORMAT = "%(levelname)s: %(message)s"

SERVICE_PROFILES = {
    "Ollama": {
        "keywords": ["ollama"],
        "classification": "LLM Runtime",
        "attack_surface": "AI Runtime Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Exposed LLM runtime API may allow unauthorized model interaction.",
        "recommendation": "Restrict runtime access to trusted hosts and require authentication.",
        "mitre_atlas_tactic": "Reconnaissance",
        "mitre_atlas_technique": "Discover AI Model Endpoints",
    },
    "Jupyter": {
        "keywords": ["jupyter", "notebook", "jupyterlab"],
        "classification": "AI Development Environment",
        "attack_surface": "Notebook Exposure",
        "risk": "Critical",
        "risk_score": 10,
        "issue": "Exposed notebook environment may allow code execution or data access.",
        "recommendation": "Require strong authentication and avoid exposing notebooks to untrusted networks.",
        "mitre_atlas_tactic": "Initial Access",
        "mitre_atlas_technique": "Exploit Public-Facing AI Development Environment",
    },
    "Streamlit": {
        "keywords": ["streamlit", "stcore", "streamlit-app"],
        "classification": "AI Web Interface",
        "attack_surface": "AI Application Exposure",
        "risk": "Medium",
        "risk_score": 5,
        "issue": "Unauthenticated AI application may expose internal workflows or data.",
        "recommendation": "Add authentication and restrict network exposure for internal AI apps.",
        "mitre_atlas_tactic": "Reconnaissance",
        "mitre_atlas_technique": "Discover Public-Facing AI Application",
    },
    "Gradio": {
        "keywords": ["gradio", "api/predict", "queue/join"],
        "classification": "AI Web Interface",
        "attack_surface": "AI Application Exposure",
        "risk": "Medium",
        "risk_score": 6,
        "issue": "Open model demo interface may expose prompts, outputs, or test models.",
        "recommendation": "Disable public sharing unless required and enforce authentication.",
        "mitre_atlas_tactic": "Reconnaissance",
        "mitre_atlas_technique": "Discover Public-Facing AI Application",
    },
    "MLFlow": {
        "keywords": ["mlflow", "experiments", "runs"],
        "classification": "AI Development Environment",
        "attack_surface": "Model Operations Exposure",
        "risk": "Medium",
        "risk_score": 6,
        "issue": "Exposed experiment tracking may reveal model metadata, artifacts, or run history.",
        "recommendation": "Restrict MLFlow access and protect model artifacts with authentication.",
        "mitre_atlas_tactic": "Collection",
        "mitre_atlas_technique": "Collect AI Artifacts",
    },
    "Open WebUI": {
        "keywords": ["open-webui", "open webui", "openwebui"],
        "classification": "AI Web Interface",
        "attack_surface": "AI Chat Interface Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Open AI chat interface may expose model access and conversation data.",
        "recommendation": "Require authentication and review user, model, and network access controls.",
        "mitre_atlas_tactic": "Initial Access",
        "mitre_atlas_technique": "Exploit Public-Facing AI Application",
    },
    "vLLM": {
        "keywords": ["vllm", "openai compatible", "openai-compatible", "/v1/chat/completions"],
        "classification": "AI Inference API",
        "attack_surface": "Inference API Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Open inference API may allow unauthorized prompts or model abuse.",
        "recommendation": "Require API authentication, rate limits, and network restrictions.",
        "mitre_atlas_tactic": "Execution",
        "mitre_atlas_technique": "Query AI Model",
    },
    "HuggingFace TGI": {
        "keywords": ["text-generation-inference", "huggingface tgi", "generate_stream"],
        "classification": "AI Inference API",
        "attack_surface": "Inference API Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Open text generation inference endpoint may allow unauthorized model usage.",
        "recommendation": "Protect inference endpoints with authentication, quotas, and network controls.",
        "mitre_atlas_tactic": "Execution",
        "mitre_atlas_technique": "Query AI Model",
    },
    "NVIDIA Triton": {
        "keywords": ["triton", "nvidia triton", "inference server", "v2/models"],
        "classification": "AI Inference API",
        "attack_surface": "Inference API Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Open model serving endpoint may expose model metadata or inference access.",
        "recommendation": "Place model serving APIs behind authentication and private networking.",
        "mitre_atlas_tactic": "Execution",
        "mitre_atlas_technique": "Query AI Model",
    },
    "TorchServe": {
        "keywords": ["torchserve", "pytorch model server", "predictions"],
        "classification": "AI Inference API",
        "attack_surface": "Inference API Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Open model prediction API may allow unauthorized inference requests.",
        "recommendation": "Restrict prediction APIs and require authentication for model access.",
        "mitre_atlas_tactic": "Execution",
        "mitre_atlas_technique": "Query AI Model",
    },
    "TensorFlow Serving": {
        "keywords": ["tensorflow serving", "tensorflow_model_server", "v1/models"],
        "classification": "AI Inference API",
        "attack_surface": "Inference API Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Open TensorFlow Serving endpoint may expose model inference capabilities.",
        "recommendation": "Restrict serving endpoints and monitor inference usage.",
        "mitre_atlas_tactic": "Execution",
        "mitre_atlas_technique": "Query AI Model",
    },
    "Ray Serve": {
        "keywords": ["ray serve", "ray dashboard", "ray"],
        "classification": "AI Runtime",
        "attack_surface": "AI Runtime Exposure",
        "risk": "High",
        "risk_score": 8,
        "issue": "Exposed distributed AI runtime may reveal workloads or allow unsafe management access.",
        "recommendation": "Keep runtime dashboards private and restrict cluster management ports.",
        "mitre_atlas_tactic": "Discovery",
        "mitre_atlas_technique": "Discover AI Infrastructure",
    },
    "Redis Vector DB": {
        "keywords": ["redis", "redis-stack", "redisearch", "vector"],
        "classification": "Vector Database",
        "attack_surface": "Vector Database Exposure",
        "risk": "High",
        "risk_score": 7,
        "issue": "Exposed vector database may reveal embeddings, retrieval data, or application memory.",
        "recommendation": "Bind Redis/vector databases to private networks and require authentication.",
        "mitre_atlas_tactic": "Collection",
        "mitre_atlas_technique": "Collect AI Application Data",
    },
    "AI Provider API": {
        "keywords": ["api.openai.com", "anthropic.com", "huggingface.co", "replicate.com", "cohere.ai"],
        "classification": "External AI Provider",
        "attack_surface": "AI Provider Communication",
        "risk": "Medium",
        "risk_score": 6,
        "issue": "Outbound AI provider communication may indicate unmanaged AI API usage.",
        "recommendation": "Review egress controls, API key handling, and approved AI provider usage.",
        "mitre_atlas_tactic": "Command and Control",
        "mitre_atlas_technique": "External AI Service Communication",
    },
    "Unknown": {
        "keywords": [],
        "classification": "Unknown",
        "attack_surface": "Unclassified Exposure",
        "risk": "Low",
        "risk_score": 2,
        "issue": "Reachable service could not be confidently classified as an AI asset.",
        "recommendation": "Review the service manually and restrict exposure if it is not intended.",
        "mitre_atlas_tactic": "Reconnaissance",
        "mitre_atlas_technique": "Discover Exposed Service",
    },
}

HTTP_TARGETS = [
    {"url": "http://localhost:11434", "expected_service": "Ollama"},
    {"url": "http://localhost:8888", "expected_service": "Jupyter"},
    {"url": "http://localhost:8501", "expected_service": "Streamlit"},
    {"url": "http://localhost:7860", "expected_service": "Gradio"},
    {"url": "http://localhost:5000", "expected_service": "MLFlow"},
    {"url": "http://localhost:3000", "expected_service": "Open WebUI"},
    {"url": "http://localhost:8000", "expected_service": "vLLM"},
    {"url": "http://localhost:8080", "expected_service": "HuggingFace TGI"},
    {"url": "http://localhost:8001", "expected_service": "NVIDIA Triton"},
    {"url": "http://localhost:8081", "expected_service": "TorchServe"},
    {"url": "http://localhost:8500", "expected_service": "TensorFlow Serving"},
    {"url": "http://localhost:8265", "expected_service": "Ray Serve"},
]

NMAP_PORT_SERVICE_HINTS = {
    "3000": "Open WebUI",
    "5000": "MLFlow",
    "6379": "Redis Vector DB",
    "7860": "Gradio",
    "8000": "vLLM",
    "8001": "NVIDIA Triton",
    "8080": "HuggingFace TGI",
    "8081": "TorchServe",
    "8265": "Ray Serve",
    "8500": "TensorFlow Serving",
    "8501": "Streamlit",
    "8888": "Jupyter",
    "11434": "Ollama",
}

CSV_COLUMNS = [
    "source",
    "discovery_source",
    "asset_name",
    "image",
    "status",
    "detected_service",
    "service_classification",
    "attack_surface_classification",
    "detection_method",
    "endpoint",
    "http_status",
    "server_header",
    "page_title",
    "exposure_category",
    "evidence",
    "issue",
    "recommendation",
    "attack_path",
    "mitre_atlas_tactic",
    "mitre_atlas_technique",
    "risk",
    "risk_score",
    "cloud_provider",
    "region",
    "subnet",
    "gpu_enabled",
    "public_exposure",
    "ai_provider",
    "provider_type",
    "outbound_ai_traffic",
    "telemetry_source",
]


def configure_logging():
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


def get_service_profile(service):
    return SERVICE_PROFILES.get(service, SERVICE_PROFILES["Unknown"])


def detect_service_from_text(text):
    normalized_text = (text or "").lower()

    for service, profile in SERVICE_PROFILES.items():
        if service == "Unknown":
            continue

        if any(keyword in normalized_text for keyword in profile["keywords"]):
            return service

    return "Unknown"


def extract_page_title(html):
    match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)

    if not match:
        return ""

    return " ".join(match.group(1).split())


def analyze_exposure(service, http_status="", response_text=""):
    normalized_text = (response_text or "").lower()
    status_code = int(http_status) if str(http_status).isdigit() else 0
    classification = get_service_profile(service)["classification"]

    if service == "Jupyter":
        return "Exposed Notebook"

    if classification in {"LLM Runtime", "AI Runtime"}:
        return "AI Runtime Exposure"

    if classification == "AI Inference API":
        return "Inference API Exposure"

    if classification == "Vector Database":
        return "Vector Database Exposure"

    login_indicators = ["login", "sign in", "password", "token"]
    has_login_prompt = any(indicator in normalized_text for indicator in login_indicators)

    if status_code in {401, 403} or has_login_prompt:
        return "Authentication Prompt Detected"

    if classification == "AI Web Interface":
        return "Unauthenticated AI Interface"

    if classification == "AI Development Environment":
        return "AI Development Service Exposure"

    return "AI Service Exposure"


def build_attack_path(service, exposure_category):
    profile = get_service_profile(service)
    return (
        f"External discovery -> {exposure_category} -> "
        f"{profile['classification']} -> {profile['mitre_atlas_technique']}"
    )


def enrich_cloud_attack_path(base_attack_path, public_exposure="", ai_provider=""):
    """Add cloud exposure and provider context to an attack path string."""
    path = base_attack_path

    if public_exposure == "true":
        path = "Public cloud exposure -> " + path

    if ai_provider:
        path = f"{path} -> outbound {ai_provider} communication"

    return path


def build_finding(
    source,
    discovery_source,
    asset_name,
    image,
    status,
    detected_service,
    detection_method,
    endpoint="",
    http_status="",
    server_header="",
    page_title="",
    exposure_category="",
    evidence="",
    cloud_provider="",
    region="",
    subnet="",
    gpu_enabled="",
    public_exposure="",
    ai_provider="",
    provider_type="",
    outbound_ai_traffic="",
    telemetry_source="",
):
    profile = get_service_profile(detected_service)
    category = exposure_category or analyze_exposure(detected_service, http_status)

    attack_path = enrich_cloud_attack_path(
        build_attack_path(detected_service, category),
        str(public_exposure).lower(),
        ai_provider,
    )

    return {
        "source": source,
        "discovery_source": discovery_source,
        "asset_name": asset_name,
        "image": image,
        "status": status,
        "detected_service": detected_service,
        "service_classification": profile["classification"],
        "attack_surface_classification": profile["attack_surface"],
        "detection_method": detection_method,
        "endpoint": endpoint,
        "http_status": http_status,
        "server_header": server_header,
        "page_title": page_title,
        "exposure_category": category,
        "evidence": evidence,
        "issue": profile["issue"],
        "recommendation": profile["recommendation"],
        "attack_path": attack_path,
        "mitre_atlas_tactic": profile["mitre_atlas_tactic"],
        "mitre_atlas_technique": profile["mitre_atlas_technique"],
        "risk": profile["risk"],
        "risk_score": profile["risk_score"],
        "cloud_provider": cloud_provider,
        "region": region,
        "subnet": subnet,
        "gpu_enabled": gpu_enabled,
        "public_exposure": public_exposure,
        "ai_provider": ai_provider,
        "provider_type": provider_type,
        "outbound_ai_traffic": outbound_ai_traffic,
        "telemetry_source": telemetry_source,
    }


def get_container_image_name(container):
    try:
        return container.image.tags[0] if container.image.tags else container.image.short_id
    except Exception:
        return "unknown"


def enumerate_docker_containers():
    findings = []

    if docker is None:
        logging.warning("Docker SDK is not installed. Run: pip install -r requirements.txt")
        return findings

    logging.info("Connecting to Docker...")

    try:
        client = docker.from_env()
        containers = client.containers.list()
    except Exception as error:
        logging.warning("Could not enumerate Docker containers: %s", error)
        return findings

    logging.info("Found %s running Docker container(s).", len(containers))

    for container in containers:
        try:
            image_name = get_container_image_name(container)
            detected_service = detect_service_from_text(image_name)

            if detected_service == "Unknown":
                logging.debug("Skipping non-AI container: %s", container.name)
                continue

            findings.append(
                build_finding(
                    source="docker",
                    discovery_source="docker_sdk",
                    asset_name=container.name,
                    image=image_name,
                    status=container.status,
                    detected_service=detected_service,
                    detection_method="container_image_keyword",
                    exposure_category=analyze_exposure(detected_service),
                    evidence=f"Container image matched AI service fingerprint: {detected_service}",
                )
            )
            logging.info("Detected %s container: %s", detected_service, container.name)
        except Exception as error:
            logging.warning("Could not process Docker container: %s", error)

    return findings


def fingerprint_http_response(target, response):
    response_text = response.text[:3000]
    server_header = response.headers.get("Server", "")
    page_title = extract_page_title(response.text)
    header_text = " ".join(f"{key}: {value}" for key, value in response.headers.items())
    combined_evidence = f"{response.url} {server_header} {page_title} {header_text} {response_text}"

    detected_service = detect_service_from_text(combined_evidence)

    if detected_service == "Unknown":
        detected_service = target["expected_service"]
        evidence = "Endpoint responded on a known AI service port"
    else:
        evidence = f"HTTP response matched AI fingerprint: {detected_service}"

    return {
        "detected_service": detected_service,
        "server_header": server_header,
        "page_title": page_title,
        "exposure_category": analyze_exposure(detected_service, response.status_code, response_text),
        "evidence": evidence,
    }


def fingerprint_http_services():
    findings = []

    if requests is None:
        logging.warning("requests is not installed. Skipping HTTP fingerprinting.")
        return findings

    session = requests.Session()

    logging.info("Probing common local AI service endpoints...")

    for target in HTTP_TARGETS:
        url = target["url"]

        try:
            response = session.get(url, timeout=3, allow_redirects=True)
        except requests.ConnectionError:
            logging.info("No HTTP service detected at %s", url)
            continue
        except requests.Timeout:
            logging.warning("HTTP probe timed out for %s", url)
            continue
        except requests.RequestException as error:
            logging.warning("HTTP probe failed for %s: %s", url, error)
            continue

        fingerprint = fingerprint_http_response(target, response)
        detected_service = fingerprint["detected_service"]

        findings.append(
            build_finding(
                source="network",
                discovery_source="http_probe",
                asset_name="localhost",
                image="",
                status="reachable",
                detected_service=detected_service,
                detection_method="http_content_fingerprint",
                endpoint=url,
                http_status=response.status_code,
                server_header=fingerprint["server_header"],
                page_title=fingerprint["page_title"],
                exposure_category=fingerprint["exposure_category"],
                evidence=fingerprint["evidence"],
            )
        )
        logging.info("Detected %s exposure at %s", detected_service, url)

    return findings


def scan_network_ports(target_host):
    findings = []

    if nmap is None:
        logging.warning("python-nmap is not installed. Run: pip install -r requirements.txt")
        return findings

    ports = ",".join(NMAP_PORT_SERVICE_HINTS.keys())
    logging.info("Running nmap discovery against %s for AI-relevant ports: %s", target_host, ports)

    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_host, ports, arguments="-sT -Pn")
    except Exception as error:
        logging.warning("nmap scan failed: %s", error)
        return findings

    for host in scanner.all_hosts():
        tcp_ports = scanner[host].get("tcp", {})

        for port, details in tcp_ports.items():
            if details.get("state") != "open":
                continue

            service = NMAP_PORT_SERVICE_HINTS.get(str(port), "Unknown")

            if service == "Unknown":
                continue

            findings.append(
                build_finding(
                    source="network",
                    discovery_source="python_nmap",
                    asset_name=host,
                    image="",
                    status="open",
                    detected_service=service,
                    detection_method="known_ai_port",
                    endpoint=f"{host}:{port}",
                    server_header=details.get("name", ""),
                    exposure_category=analyze_exposure(service),
                    evidence=f"Open AI-relevant TCP port {port} detected by nmap",
                )
            )
            logging.info("nmap detected possible %s exposure on %s:%s", service, host, port)

    return findings


def enumerate_kubernetes_workloads():
    findings = []

    try:
        from kubernetes import client, config
    except ImportError:
        logging.warning("Kubernetes SDK is not installed. Skipping Kubernetes discovery.")
        return findings

    logging.info("Connecting to Kubernetes using the current kubeconfig...")

    try:
        config.load_kube_config()
        core_api = client.CoreV1Api()
        pods = core_api.list_pod_for_all_namespaces(watch=False)
    except Exception as error:
        logging.warning("Could not enumerate Kubernetes pods: %s", error)
        return findings

    logging.info("Found %s Kubernetes pod(s).", len(pods.items))

    for pod in pods.items:
        for container in pod.spec.containers:
            try:
                detected_service = detect_service_from_text(container.image)

                if detected_service == "Unknown":
                    continue

                findings.append(
                    build_finding(
                        source="kubernetes",
                        discovery_source="kubernetes_api",
                        asset_name=f"{pod.metadata.namespace}/{pod.metadata.name}",
                        image=container.image,
                        status=pod.status.phase,
                        detected_service=detected_service,
                        detection_method="pod_image_keyword",
                        exposure_category=analyze_exposure(detected_service),
                        evidence=f"Kubernetes pod image matched AI service fingerprint: {detected_service}",
                    )
                )
                logging.info(
                    "Detected %s Kubernetes workload: %s/%s",
                    detected_service,
                    pod.metadata.namespace,
                    pod.metadata.name,
                )
            except Exception as error:
                logging.warning("Could not process Kubernetes container: %s", error)

    return findings


def analyze_cloud_asset_exposure(asset):
    """Create a cloud-native exposure category for a simulated cloud asset."""
    public_exposure = asset.get("public_exposure", False)
    gpu_enabled = asset.get("gpu_enabled", False)
    open_ports = asset.get("open_ports", [])
    service = asset.get("detected_service", "Unknown")

    if public_exposure and gpu_enabled:
        return "Public GPU AI Workload"

    if service in {"vLLM", "HuggingFace TGI", "NVIDIA Triton", "TorchServe", "TensorFlow Serving"}:
        return "Cloud Inference API Exposure"

    if service == "Redis Vector DB":
        return "Cloud Vector Database Exposure"

    if public_exposure and open_ports:
        return "Public Cloud AI Service Exposure"

    return analyze_exposure(service)


def discover_cloud_ai_assets():
    """Simulate cloud compute, GPU, and AI workload discovery."""
    findings = []
    assets = discover_cloud_assets()

    logging.info("Loaded %s simulated cloud asset(s).", len(assets))

    for asset in assets:
        detected_service = asset.get("detected_service", "Unknown")
        exposure_category = analyze_cloud_asset_exposure(asset)
        public_exposure = str(asset.get("public_exposure", False)).lower()
        gpu_enabled = str(asset.get("gpu_enabled", False)).lower()

        findings.append(
            build_finding(
                source="cloud",
                discovery_source="mock_cloud_inventory",
                asset_name=asset.get("instance_name", "unknown-cloud-asset"),
                image="",
                status="running",
                detected_service=detected_service,
                detection_method="cloud_asset_metadata",
                endpoint=",".join(str(port) for port in asset.get("open_ports", [])),
                exposure_category=exposure_category,
                evidence=summarize_asset(asset),
                cloud_provider=asset.get("cloud_provider", "GenericCloud"),
                region=asset.get("region", ""),
                subnet=asset.get("subnet", ""),
                gpu_enabled=gpu_enabled,
                public_exposure=public_exposure,
                telemetry_source="cloud_asset_inventory",
            )
        )

        logging.info(
            "Cloud discovery detected %s on %s.",
            detected_service,
            asset.get("instance_name", "unknown-cloud-asset"),
        )

    return findings


def analyze_cloud_ai_logs():
    """Simulate cloud telemetry analysis for outbound AI provider traffic."""
    findings = []
    detections = analyze_ai_provider_traffic()

    logging.info("Detected %s AI provider telemetry event(s).", len(detections))

    for event in detections:
        ai_provider = event.get("provider", "")
        destination = event.get("destination_domain", "")
        telemetry_source = event.get("telemetry_source", "cloud_logs")

        findings.append(
            build_finding(
                source="cloud",
                discovery_source="mock_cloud_telemetry",
                asset_name=event.get("asset_name", "unknown-cloud-asset"),
                image="",
                status="observed",
                detected_service="AI Provider API",
                detection_method="cloud_log_ai_provider_detection",
                endpoint=f"{destination}:{event.get('destination_port', 443)}",
                exposure_category="AI API Usage Exposure",
                evidence=(
                    f"{telemetry_source} observed outbound traffic to {destination} "
                    f"with {event.get('bytes_out', 0)} bytes sent"
                ),
                ai_provider=ai_provider,
                provider_type=event.get("provider_type", ""),
                outbound_ai_traffic="true",
                telemetry_source=telemetry_source,
            )
        )

        logging.info("Cloud telemetry detected outbound %s communication.", ai_provider)

    return findings


def correlate_cloud_attack_paths(cloud_asset_findings, cloud_log_findings):
    """Correlate cloud assets and AI provider traffic into attack path findings."""
    findings = []
    logs_by_asset = {}

    for log_finding in cloud_log_findings:
        logs_by_asset.setdefault(log_finding["asset_name"], []).append(log_finding)

    for asset_finding in cloud_asset_findings:
        related_logs = logs_by_asset.get(asset_finding["asset_name"], [])

        if not related_logs:
            continue

        for log_finding in related_logs:
            findings.append(
                build_finding(
                    source="cloud",
                    discovery_source="cloud_correlation_engine",
                    asset_name=asset_finding["asset_name"],
                    image="",
                    status="correlated",
                    detected_service=asset_finding["detected_service"],
                    detection_method="asset_telemetry_correlation",
                    endpoint=asset_finding.get("endpoint", ""),
                    exposure_category="Correlated Cloud AI Exposure",
                    evidence=(
                        f"Correlated {asset_finding['attack_surface_classification']} with "
                        f"outbound {log_finding['ai_provider']} communication"
                    ),
                    cloud_provider=asset_finding.get("cloud_provider", ""),
                    region=asset_finding.get("region", ""),
                    subnet=asset_finding.get("subnet", ""),
                    gpu_enabled=asset_finding.get("gpu_enabled", ""),
                    public_exposure=asset_finding.get("public_exposure", ""),
                    ai_provider=log_finding.get("ai_provider", ""),
                    provider_type=log_finding.get("provider_type", ""),
                    outbound_ai_traffic="true",
                    telemetry_source="asset_and_telemetry_correlation",
                )
            )

            logging.info(
                "Correlated cloud attack path for %s with %s.",
                asset_finding["asset_name"],
                log_finding["ai_provider"],
            )

    return findings


def save_findings(findings, output_file=FINDINGS_FILE):
    temporary_file = output_file.with_suffix(".tmp")

    try:
        with temporary_file.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(findings)

        temporary_file.replace(output_file)
    except OSError as error:
        logging.error("Could not write findings to %s: %s", output_file, error)
        raise


def main():
    parser = argparse.ArgumentParser(description="AI attack surface discovery scanner")
    parser.add_argument(
        "--include-kubernetes",
        action="store_true",
        help="Also scan Kubernetes pods from the current kubeconfig",
    )
    parser.add_argument(
        "--network-scan",
        action="store_true",
        help="Run python-nmap against AI-relevant ports",
    )
    parser.add_argument(
        "--network-target",
        default="127.0.0.1",
        help="Host or CIDR to scan when --network-scan is enabled",
    )
    parser.add_argument(
        "--cloud-discovery",
        action="store_true",
        help="Run simulated cloud AI asset discovery",
    )
    parser.add_argument(
        "--cloud-logs",
        action="store_true",
        help="Run simulated cloud telemetry and AI provider log analysis",
    )
    parser.add_argument("--debug", action="store_true", help="Show debug logging messages")
    args = parser.parse_args()

    configure_logging()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("Starting enterprise AI attack surface discovery scan.")

    findings = []
    findings.extend(enumerate_docker_containers())
    findings.extend(fingerprint_http_services())

    if args.network_scan:
        findings.extend(scan_network_ports(args.network_target))

    if args.include_kubernetes:
        findings.extend(enumerate_kubernetes_workloads())

    cloud_asset_findings = []
    cloud_log_findings = []

    if args.cloud_discovery:
        cloud_asset_findings = discover_cloud_ai_assets()
        findings.extend(cloud_asset_findings)

    if args.cloud_logs:
        cloud_log_findings = analyze_cloud_ai_logs()
        findings.extend(cloud_log_findings)

    if cloud_asset_findings and cloud_log_findings:
        findings.extend(correlate_cloud_attack_paths(cloud_asset_findings, cloud_log_findings))

    save_findings(findings)
    logging.info("Saved %s AI exposure finding(s) to %s.", len(findings), FINDINGS_FILE)


if __name__ == "__main__":
    main()
