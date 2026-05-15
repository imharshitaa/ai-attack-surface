"""
Mock cloud asset discovery for AI attack surface visibility.

This module is intentionally cloud-provider neutral. In a real platform these
records would come from cloud APIs. Here we return local mock data so the
project remains runnable without credentials.
"""


def discover_cloud_assets():
    """Return simulated cloud compute assets with AI workload metadata."""
    return [
        {
            "cloud_provider": "GenericCloud",
            "region": "us-east-1",
            "subnet": "public-ai-subnet",
            "instance_name": "gpu-inference-public-01",
            "public_exposure": True,
            "gpu_enabled": True,
            "tags": {"team": "ml-platform", "env": "dev", "workload": "vllm"},
            "open_ports": [22, 8000],
            "ai_workload_indicators": ["gpu", "vllm", "inference-api"],
            "detected_service": "vLLM",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "us-east-1",
            "subnet": "private-ai-subnet",
            "instance_name": "gpu-training-private-01",
            "public_exposure": False,
            "gpu_enabled": True,
            "tags": {"team": "research", "env": "prod", "workload": "ray-serve"},
            "open_ports": [8265],
            "ai_workload_indicators": ["gpu", "ray", "distributed-training"],
            "detected_service": "Ray Serve",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "us-west-2",
            "subnet": "private-research-subnet",
            "instance_name": "research-notebook-02",
            "public_exposure": False,
            "gpu_enabled": True,
            "tags": {"team": "research", "env": "staging", "workload": "jupyter"},
            "open_ports": [8888],
            "ai_workload_indicators": ["gpu", "jupyter", "notebook"],
            "detected_service": "Jupyter",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "us-west-2",
            "subnet": "public-research-subnet",
            "instance_name": "research-notebook-public-03",
            "public_exposure": True,
            "gpu_enabled": True,
            "tags": {"team": "research", "env": "dev", "workload": "jupyter"},
            "open_ports": [22, 8888],
            "ai_workload_indicators": ["gpu", "jupyter", "public-notebook"],
            "detected_service": "Jupyter",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "eu-central-1",
            "subnet": "public-demo-subnet",
            "instance_name": "genai-demo-web-01",
            "public_exposure": True,
            "gpu_enabled": False,
            "tags": {"team": "apps", "env": "demo", "workload": "gradio"},
            "open_ports": [7860],
            "ai_workload_indicators": ["gradio", "model-demo"],
            "detected_service": "Gradio",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "eu-central-1",
            "subnet": "private-app-subnet",
            "instance_name": "internal-streamlit-app-01",
            "public_exposure": False,
            "gpu_enabled": False,
            "tags": {"team": "apps", "env": "prod", "workload": "streamlit"},
            "open_ports": [8501],
            "ai_workload_indicators": ["streamlit", "internal-ai-app"],
            "detected_service": "Streamlit",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "ap-south-1",
            "subnet": "public-inference-subnet",
            "instance_name": "tgi-inference-public-01",
            "public_exposure": True,
            "gpu_enabled": True,
            "tags": {"team": "ml-platform", "env": "staging", "workload": "tgi"},
            "open_ports": [22, 8080],
            "ai_workload_indicators": ["gpu", "huggingface-tgi", "inference-api"],
            "detected_service": "HuggingFace TGI",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "ap-south-1",
            "subnet": "private-serving-subnet",
            "instance_name": "triton-serving-private-01",
            "public_exposure": False,
            "gpu_enabled": True,
            "tags": {"team": "ml-platform", "env": "prod", "workload": "triton"},
            "open_ports": [8001],
            "ai_workload_indicators": ["gpu", "triton", "model-serving"],
            "detected_service": "NVIDIA Triton",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "us-east-1",
            "subnet": "shared-data-subnet",
            "instance_name": "rag-vector-cache-01",
            "public_exposure": True,
            "gpu_enabled": False,
            "tags": {"team": "platform", "env": "dev", "workload": "redis-vector"},
            "open_ports": [6379],
            "ai_workload_indicators": ["redis", "vector", "rag"],
            "detected_service": "Redis Vector DB",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "us-east-2",
            "subnet": "private-mlops-subnet",
            "instance_name": "mlflow-tracking-01",
            "public_exposure": False,
            "gpu_enabled": False,
            "tags": {"team": "mlops", "env": "prod", "workload": "mlflow"},
            "open_ports": [5000],
            "ai_workload_indicators": ["mlflow", "experiment-tracking"],
            "detected_service": "MLFlow",
        },
        {
            "cloud_provider": "GenericCloud",
            "region": "us-east-2",
            "subnet": "public-chat-subnet",
            "instance_name": "open-webui-public-01",
            "public_exposure": True,
            "gpu_enabled": False,
            "tags": {"team": "product", "env": "demo", "workload": "open-webui"},
            "open_ports": [3000],
            "ai_workload_indicators": ["open-webui", "chat-ui"],
            "detected_service": "Open WebUI",
        },
    ]


def summarize_asset(asset):
    """Create a compact evidence string for a cloud asset."""
    indicators = ", ".join(asset.get("ai_workload_indicators", []))
    ports = ", ".join(str(port) for port in asset.get("open_ports", []))
    tags = ", ".join(f"{key}={value}" for key, value in asset.get("tags", {}).items())
    return f"Cloud asset indicators: {indicators}; open ports: {ports}; tags: {tags}"
