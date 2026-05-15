# AI Attack Surface Discovery Platform - Technical Documentation

Repository: `https://github.com/imharshitaa/ai-attack-surface.git`

This document explains the actual code workflow for the AI Attack Surface Discovery platform. It covers local discovery, cloud-native mock discovery, telemetry analysis, AI provider detection, finding generation, attack path correlation, and dashboard metric calculation.

## 1. Project Purpose

The project simulates a lightweight AI security visibility platform. It discovers AI workloads from local containers, HTTP endpoints, optional Kubernetes pods, mock cloud inventory, and mock cloud telemetry.

The platform is designed to show how security teams can move from basic network scanning to cloud-native AI asset discovery and telemetry-driven exposure analysis.

The main outputs are:

- `findings.csv`
- Streamlit dashboard views
- AI-specific exposure classifications
- provider communication detections
- attack path style findings

## 2. Main Files

| File | Purpose |
| --- | --- |
| `scanner.py` | Main scanner and finding generation engine |
| `cloud_discovery.py` | Mock cloud asset discovery module |
| `cloud_logs.py` | Mock cloud telemetry and AI provider detection module |
| `dashboard.py` | Streamlit dashboard for visualizing findings |
| `findings.csv` | Scanner output consumed by the dashboard |
| `requirements.txt` | Python dependencies |
| `README.md` | Project overview and usage instructions |

## 3. End-to-End Workflow

The scanner follows this execution flow:

1. Parse command-line flags.
2. Configure logging.
3. Enumerate Docker containers.
4. Probe known local AI HTTP endpoints.
5. Optionally run `python-nmap` network scanning.
6. Optionally enumerate Kubernetes pod images.
7. Optionally load mock cloud asset inventory.
8. Optionally analyze mock cloud telemetry logs.
9. If both cloud assets and cloud logs exist, correlate them into attack paths.
10. Save all findings to `findings.csv`.
11. The dashboard loads `findings.csv`, normalizes missing columns, calculates metrics, and renders tables/charts.

## 4. `cloud_discovery.py`

This module simulates cloud asset inventory discovery. It is generic and not tied to AWS, Azure, or GCP.

### `discover_cloud_assets()`

This function returns a list of dictionaries. Each dictionary represents one cloud compute asset.

Each cloud asset includes:

- `cloud_provider`
- `region`
- `subnet`
- `instance_name`
- `public_exposure`
- `gpu_enabled`
- `tags`
- `open_ports`
- `ai_workload_indicators`
- `detected_service`

The current mock dataset includes more than 10 cloud assets. Examples include:

- public GPU inference VM running `vLLM`
- private GPU training VM running `Ray Serve`
- private and public Jupyter notebook assets
- public Gradio demo VM
- private Streamlit app VM
- public HuggingFace TGI inference VM
- private NVIDIA Triton serving VM
- Redis vector database asset
- MLFlow tracking server
- Open WebUI public chat interface

The function does not call any cloud API. It returns local mock records so the project can run without credentials.

The scanner consumes this data in `discover_cloud_ai_assets()`.

### `summarize_asset(asset)`

This function receives one cloud asset dictionary.

It extracts:

- AI workload indicators
- open ports
- tags

Then it creates a compact evidence string.

Example logic:

```text
Cloud asset indicators: gpu, vllm, inference-api; open ports: 22, 8000; tags: team=ml-platform, env=dev, workload=vllm
```

This evidence string is placed into the `evidence` column in `findings.csv`.

## 5. `cloud_logs.py`

This module simulates telemetry-driven discovery. It models activity logs, flow logs, DNS logs, and outbound connection records.

### `AI_PROVIDER_DOMAINS`

This dictionary maps known AI provider domains to provider metadata.

Mappings include:

| Domain | Provider | Provider Type |
| --- | --- | --- |
| `api.openai.com` | OpenAI | LLM API Provider |
| `anthropic.com` | Anthropic | LLM API Provider |
| `huggingface.co` | HuggingFace | Model Hub and Inference Provider |
| `replicate.com` | Replicate | Hosted Model Inference Provider |
| `cohere.ai` | Cohere | LLM API Provider |

The scanner uses this metadata to classify outbound AI traffic.

### `generate_mock_cloud_logs()`

This function returns simulated telemetry records.

The dataset includes more than 20 telemetry events. Events contain:

- `telemetry_source`
- `asset_name`
- `destination_domain`
- `destination_port`
- `action`
- `bytes_out`

Telemetry sources include:

- `dns_logs`
- `flow_logs`
- `activity_logs`

Some events point to AI providers. Some events point to non-AI domains such as update servers. Non-AI domains are included so provider detection has to filter relevant events instead of assuming every log is AI-related.

### `detect_ai_provider(domain)`

This function receives a destination domain string.

The logic is:

1. Convert the domain to lowercase.
2. Loop through `AI_PROVIDER_DOMAINS`.
3. Check whether a known provider domain appears inside the destination domain.
4. Return the matching provider metadata.
5. If no provider matches, return empty provider fields.

Example:

```text
api.openai.com -> OpenAI
model-cache.huggingface.co -> HuggingFace
updates.example.com -> no provider
```

### `analyze_ai_provider_traffic(log_events=None)`

This function receives optional telemetry events. If no events are provided, it calls `generate_mock_cloud_logs()`.

The logic is:

1. Load telemetry events.
2. For each event, read `destination_domain`.
3. Call `detect_ai_provider(destination_domain)`.
4. If no provider is found, skip the event.
5. If a provider is found, copy the event.
6. Add `provider` and `provider_type`.
7. Append the enriched event to the detections list.
8. Return only AI-provider-related telemetry events.

This function is used by `scanner.py` in `analyze_cloud_ai_logs()`.

## 6. `scanner.py`

`scanner.py` is the main execution engine.

It imports:

- `discover_cloud_assets`
- `summarize_asset`
- `analyze_ai_provider_traffic`

It also optionally imports:

- `requests`
- `docker`
- `nmap`

These optional imports allow the cloud mock mode to run even when local scanner dependencies are not installed.

## 7. Scanner Constants

### `FINDINGS_FILE`

Defines the scanner output file:

```python
FINDINGS_FILE = Path("findings.csv")
```

### `SERVICE_PROFILES`

This is the scanner's main service metadata registry.

Each service profile contains:

- keywords used for detection
- service classification
- attack surface classification
- risk severity
- numeric risk score
- issue description
- recommendation
- MITRE ATLAS tactic
- MITRE ATLAS technique

Example service types:

- `Ollama`
- `Jupyter`
- `Streamlit`
- `Gradio`
- `MLFlow`
- `Open WebUI`
- `vLLM`
- `HuggingFace TGI`
- `NVIDIA Triton`
- `TorchServe`
- `TensorFlow Serving`
- `Ray Serve`
- `Redis Vector DB`
- `AI Provider API`

The scanner uses this dictionary whenever it needs to enrich a finding with security context.

### `HTTP_TARGETS`

This list defines local HTTP endpoints to probe.

Each target has:

- `url`
- `expected_service`

Example:

```python
{"url": "http://localhost:8000", "expected_service": "vLLM"}
```

If an endpoint responds but content fingerprinting is inconclusive, the scanner uses the expected service for that well-known port.

### `NMAP_PORT_SERVICE_HINTS`

This dictionary maps AI-relevant ports to likely AI services.

Example:

```python
"6379": "Redis Vector DB"
"8888": "Jupyter"
"11434": "Ollama"
```

This prevents the network scanner from producing generic open-port findings. It only records ports that are meaningful for AI exposure analysis.

### `CSV_COLUMNS`

This list defines the complete schema written to `findings.csv`.

It includes local, cloud, telemetry, risk, and attack path fields:

- `source`
- `discovery_source`
- `asset_name`
- `detected_service`
- `service_classification`
- `attack_surface_classification`
- `exposure_category`
- `issue`
- `recommendation`
- `attack_path`
- `risk`
- `risk_score`
- `cloud_provider`
- `region`
- `subnet`
- `gpu_enabled`
- `public_exposure`
- `ai_provider`
- `provider_type`
- `outbound_ai_traffic`
- `telemetry_source`

## 8. Scanner Functions

### `configure_logging()`

This function configures console logging.

It sets:

- log level: `INFO`
- message format: `LEVEL: message`

The scanner uses logging instead of raw `print()` so status messages are consistent.

### `get_service_profile(service)`

This function receives a service name.

The logic is:

1. Look up the service in `SERVICE_PROFILES`.
2. If found, return that profile.
3. If missing, return the `Unknown` profile.

This avoids crashes when a service name is unexpected.

### `detect_service_from_text(text)`

This function fingerprints AI services from text.

The logic is:

1. Convert input text to lowercase.
2. Loop through all service profiles except `Unknown`.
3. For each service, loop through its keyword list.
4. If any keyword appears in the text, return that service name.
5. If no keyword matches, return `Unknown`.

This is used for:

- Docker image names
- Kubernetes pod image names
- HTTP headers
- HTTP body text
- page titles

### `extract_page_title(html)`

This function extracts the HTML `<title>` value from an HTTP response body.

The logic is:

1. Run a regular expression against the HTML.
2. If no title exists, return an empty string.
3. If a title exists, collapse extra whitespace.
4. Return the title.

The page title becomes part of the HTTP fingerprint and is also written to `findings.csv`.

### `analyze_exposure(service, http_status="", response_text="")`

This function turns a detected service into an AI-specific exposure category.

The logic is:

1. Get the service classification from `SERVICE_PROFILES`.
2. If service is `Jupyter`, return `Exposed Notebook`.
3. If classification is `LLM Runtime` or `AI Runtime`, return `AI Runtime Exposure`.
4. If classification is `AI Inference API`, return `Inference API Exposure`.
5. If classification is `Vector Database`, return `Vector Database Exposure`.
6. Look for login indicators such as `login`, `sign in`, `password`, or `token`.
7. If HTTP status is `401` or `403`, or if login indicators are present, return `Authentication Prompt Detected`.
8. If classification is `AI Web Interface`, return `Unauthenticated AI Interface`.
9. If classification is `AI Development Environment`, return `AI Development Service Exposure`.
10. Otherwise return `AI Service Exposure`.

This keeps the output AI-specific instead of generic.

### `build_attack_path(service, exposure_category)`

This function creates a basic attack path string.

The logic is:

1. Get the service profile.
2. Read the service classification.
3. Read the MITRE ATLAS technique.
4. Return a path in this structure:

```text
External discovery -> exposure category -> service classification -> MITRE ATLAS technique
```

Example:

```text
External discovery -> Exposed Notebook -> AI Development Environment -> Exploit Public-Facing AI Development Environment
```

### `enrich_cloud_attack_path(base_attack_path, public_exposure="", ai_provider="")`

This function adds cloud context to attack paths.

The logic is:

1. Start with the base attack path.
2. If `public_exposure` is `true`, prefix the path with `Public cloud exposure`.
3. If `ai_provider` exists, append outbound provider communication.
4. Return the enriched path.

Example:

```text
Public cloud exposure -> External discovery -> Public GPU AI Workload -> AI Inference API -> Query AI Model -> outbound OpenAI communication
```

### `build_finding(...)`

This is the central finding factory.

It receives raw detection values and returns one normalized dictionary matching `CSV_COLUMNS`.

The logic is:

1. Look up the service profile.
2. Determine the exposure category.
3. Build a base attack path.
4. Enrich the attack path with cloud and AI provider context.
5. Copy service metadata into the row:
   - service classification
   - attack surface classification
   - issue
   - recommendation
   - MITRE ATLAS tactic
   - MITRE ATLAS technique
   - risk
   - risk score
6. Copy runtime metadata into the row:
   - source
   - discovery source
   - endpoint
   - HTTP status
   - server header
   - page title
7. Copy cloud and telemetry metadata into the row:
   - cloud provider
   - region
   - subnet
   - GPU enabled
   - public exposure
   - AI provider
   - provider type
   - outbound AI traffic
   - telemetry source
8. Return the finding dictionary.

Every scanner path eventually calls `build_finding()`.

### `get_container_image_name(container)`

This function extracts a Docker image name from a container object.

The logic is:

1. If the image has tags, return the first tag.
2. If no tag exists, return the short image ID.
3. If Docker metadata access fails, return `unknown`.

### `enumerate_docker_containers()`

This function discovers running Docker containers.

The logic is:

1. If Docker SDK is missing, log a warning and return no findings.
2. Connect to Docker using `docker.from_env()`.
3. List running containers.
4. For each container, extract the image name.
5. Fingerprint the image name with `detect_service_from_text()`.
6. Skip containers that are not AI-related.
7. Create a finding with:
   - source: `docker`
   - discovery source: `docker_sdk`
   - detection method: `container_image_keyword`
8. Return Docker findings.

### `fingerprint_http_response(target, response)`

This function fingerprints an HTTP response.

The logic is:

1. Read the first 3000 characters of the response body.
2. Read the `Server` header.
3. Extract the page title.
4. Combine URL, server header, page title, all headers, and body text.
5. Run `detect_service_from_text()` against the combined evidence.
6. If no service is detected, use the expected service for the known port.
7. Run `analyze_exposure()` to create the exposure category.
8. Return detected service, server header, page title, exposure category, and evidence.

### `fingerprint_http_services()`

This function probes common local AI service ports.

The logic is:

1. If `requests` is missing, log a warning and skip HTTP scanning.
2. Create a `requests.Session()`.
3. Loop through `HTTP_TARGETS`.
4. Send a GET request to each target with a timeout.
5. Ignore connection failures.
6. Log timeout and request errors.
7. Fingerprint reachable responses with `fingerprint_http_response()`.
8. Build findings with:
   - source: `network`
   - discovery source: `http_probe`
   - detection method: `http_content_fingerprint`
9. Return HTTP findings.

### `scan_network_ports(target_host)`

This function performs optional `python-nmap` scanning.

The logic is:

1. If `python-nmap` is missing, log a warning and return no findings.
2. Build a comma-separated list of AI-relevant ports from `NMAP_PORT_SERVICE_HINTS`.
3. Run nmap with `-sT -Pn`.
4. Loop through hosts and TCP ports.
5. Keep only ports in `open` state.
6. Map open ports to likely AI services.
7. Skip unknown ports.
8. Build findings with:
   - source: `network`
   - discovery source: `python_nmap`
   - detection method: `known_ai_port`
9. Return nmap findings.

### `enumerate_kubernetes_workloads()`

This function performs optional Kubernetes pod image discovery.

The logic is:

1. Import Kubernetes client and config.
2. Load the current kubeconfig.
3. List pods across all namespaces.
4. Loop through pod containers.
5. Fingerprint each container image.
6. Skip non-AI images.
7. Build findings with:
   - source: `kubernetes`
   - discovery source: `kubernetes_api`
   - detection method: `pod_image_keyword`
8. Return Kubernetes findings.

### `analyze_cloud_asset_exposure(asset)`

This function classifies mock cloud asset exposure.

The logic is:

1. Read `public_exposure`.
2. Read `gpu_enabled`.
3. Read open ports.
4. Read detected service.
5. If the asset is public and GPU-enabled, return `Public GPU AI Workload`.
6. If service is an inference server, return `Cloud Inference API Exposure`.
7. If service is Redis Vector DB, return `Cloud Vector Database Exposure`.
8. If the asset is public and has open ports, return `Public Cloud AI Service Exposure`.
9. Otherwise fall back to `analyze_exposure(service)`.

This makes cloud findings more specific than local network findings.

### `discover_cloud_ai_assets()`

This function converts mock cloud assets into findings.

The logic is:

1. Call `discover_cloud_assets()` from `cloud_discovery.py`.
2. Loop through each asset.
3. Read the detected service.
4. Classify exposure using `analyze_cloud_asset_exposure()`.
5. Convert boolean values like `gpu_enabled` and `public_exposure` to lowercase strings.
6. Call `summarize_asset(asset)` to generate evidence.
7. Build a finding with:
   - source: `cloud`
   - discovery source: `mock_cloud_inventory`
   - detection method: `cloud_asset_metadata`
   - cloud provider
   - region
   - subnet
   - GPU enabled status
   - public exposure status
   - telemetry source: `cloud_asset_inventory`
8. Return cloud asset findings.

### `analyze_cloud_ai_logs()`

This function converts AI provider telemetry detections into findings.

The logic is:

1. Call `analyze_ai_provider_traffic()` from `cloud_logs.py`.
2. Loop through AI-provider telemetry detections.
3. Read provider name, provider type, destination domain, destination port, and telemetry source.
4. Build a finding with:
   - source: `cloud`
   - discovery source: `mock_cloud_telemetry`
   - detected service: `AI Provider API`
   - detection method: `cloud_log_ai_provider_detection`
   - exposure category: `AI API Usage Exposure`
   - outbound AI traffic: `true`
   - AI provider
   - provider type
   - telemetry source
5. Return telemetry findings.

### `correlate_cloud_attack_paths(cloud_asset_findings, cloud_log_findings)`

This function creates correlated attack path findings from cloud inventory and telemetry.

The logic is:

1. Create an empty dictionary called `logs_by_asset`.
2. Loop through cloud log findings.
3. Group log findings by `asset_name`.
4. Loop through cloud asset findings.
5. Find related log findings for the same asset.
6. If no related logs exist, skip that asset.
7. For each related log, build a correlated finding with:
   - source: `cloud`
   - discovery source: `cloud_correlation_engine`
   - detection method: `asset_telemetry_correlation`
   - exposure category: `Correlated Cloud AI Exposure`
   - original cloud provider, region, subnet, GPU status, and public exposure
   - correlated AI provider
   - outbound AI traffic: `true`
   - telemetry source: `asset_and_telemetry_correlation`
8. Return correlated findings.

Example:

```text
gpu-inference-public-01 exists in cloud inventory
gpu-inference-public-01 also connects to api.openai.com
correlation finding is generated
```

The attack path becomes:

```text
Public cloud exposure -> External discovery -> Correlated Cloud AI Exposure -> AI Inference API -> Query AI Model -> outbound OpenAI communication
```

### `save_findings(findings, output_file=FINDINGS_FILE)`

This function writes findings to CSV.

The logic is:

1. Create a temporary file path ending in `.tmp`.
2. Open the temporary file.
3. Write CSV headers from `CSV_COLUMNS`.
4. Write all finding rows.
5. Replace the old `findings.csv` with the temporary file.
6. If writing fails, log the error and raise it.

Using a temporary file helps avoid partially written CSV output.

### `main()`

This function controls scanner execution.

The logic is:

1. Define command-line arguments:
   - `--include-kubernetes`
   - `--network-scan`
   - `--network-target`
   - `--cloud-discovery`
   - `--cloud-logs`
   - `--debug`
2. Configure logging.
3. Enable debug logging if requested.
4. Start with an empty findings list.
5. Always run Docker discovery.
6. Always run HTTP fingerprinting.
7. If `--network-scan` is passed, run nmap discovery.
8. If `--include-kubernetes` is passed, run Kubernetes discovery.
9. If `--cloud-discovery` is passed, run mock cloud asset discovery.
10. If `--cloud-logs` is passed, run mock cloud telemetry analysis.
11. If both cloud asset and cloud log findings exist, run correlation.
12. Save all findings to `findings.csv`.

## 9. Command-Line Usage

Run local discovery:

```powershell
python scanner.py
```

Run cloud asset discovery:

```powershell
python scanner.py --cloud-discovery
```

Run cloud telemetry analysis:

```powershell
python scanner.py --cloud-logs
```

Run cloud inventory, telemetry, and correlation:

```powershell
python scanner.py --cloud-discovery --cloud-logs
```

Run everything:

```powershell
python scanner.py --network-scan --include-kubernetes --cloud-discovery --cloud-logs
```

## 10. How Findings Are Generated

Every finding is generated through `build_finding()`.

Input sources can be:

- Docker container image metadata
- HTTP service fingerprinting
- nmap open AI-relevant ports
- Kubernetes pod image metadata
- mock cloud asset inventory
- mock cloud telemetry logs
- cloud asset plus telemetry correlation

Each source sends raw evidence to `build_finding()`.

`build_finding()` enriches that raw evidence with:

- service classification
- attack surface classification
- exposure category
- issue
- recommendation
- risk
- risk score
- MITRE ATLAS mapping
- cloud fields
- AI provider fields
- telemetry fields
- attack path

The final dictionary is written as one row in `findings.csv`.

## 11. How Mixed Risk Levels Are Produced

Risk comes from `SERVICE_PROFILES`.

Examples:

- `Jupyter` is `Critical` with score `10`.
- `vLLM`, `Ollama`, `Open WebUI`, `Ray Serve`, `NVIDIA Triton`, and `HuggingFace TGI` are `High`.
- `Streamlit`, `Gradio`, `MLFlow`, and `AI Provider API` are `Medium`.
- `Unknown` is `Low`.

Because the mock cloud inventory includes notebooks, inference APIs, web interfaces, vector databases, and provider API traffic, the generated CSV contains mixed risk levels.

## 12. `dashboard.py`

The dashboard reads and visualizes `findings.csv`.

### `DEFAULT_COLUMNS`

This dictionary defines fallback values for expected columns.

It prevents Streamlit crashes when a CSV is incomplete.

Examples:

- missing `risk` becomes `Unknown`
- missing `risk_score` becomes `0`
- missing `asset_name` becomes `unknown-asset`
- missing `gpu_enabled` becomes `false`
- missing `outbound_ai_traffic` becomes `false`

### `load_findings(path)`

This function loads the CSV with `pandas.read_csv()`.

It is decorated with `@st.cache_data`, so Streamlit can cache the loaded data and avoid unnecessary reloads.

### `normalize_findings(dataframe)`

This function makes dashboard input safe.

The logic is:

1. Copy the dataframe.
2. Loop through `DEFAULT_COLUMNS`.
3. Add any missing columns with default values.
4. Replace missing or empty `risk` with `Unknown`.
5. Convert `risk_score` to numeric.
6. Replace invalid risk scores with `0`.
7. Replace missing asset names with `unknown-asset`.
8. Replace missing detected services with `Unknown`.
9. Normalize `gpu_enabled`, `public_exposure`, and `outbound_ai_traffic` to lowercase strings.
10. Build a default attack path when `attack_path` is missing.
11. Return the normalized dataframe.

This is why the dashboard does not crash when scanner output is partial.

### `available_columns(dataframe, columns)`

This function returns only columns that exist in the dataframe.

It is used before displaying tables so Streamlit does not try to render missing fields.

### `truthy_count(series)`

This function counts boolean-like strings.

It treats these values as true:

- `true`
- `yes`
- `1`

It is used to calculate:

- GPU workload count
- public cloud asset count
- outbound AI traffic count

## 13. Dashboard Metric Calculation

After loading and normalizing findings, the dashboard calculates:

### Total Findings

```python
total_findings = len(findings)
```

This counts every row in `findings.csv`.

### Critical Findings

```python
critical_count = len(findings[findings["risk"] == "Critical"])
```

This counts rows where risk is exactly `Critical`.

### High Findings

```python
high_count = len(findings[findings["risk"] == "High"])
```

This counts rows where risk is exactly `High`.

### AI Services

```python
service_count = findings["detected_service"].nunique()
```

This counts unique detected AI services.

### Average Risk Score

```python
avg_risk = round(findings["risk_score"].mean(), 1)
```

This averages numeric risk scores and rounds to one decimal place.

### Discovery Sources

```python
source_count = findings["discovery_source"].nunique()
```

This counts unique discovery methods.

### GPU Workloads

```python
gpu_count = truthy_count(findings["gpu_enabled"])
```

This counts rows where `gpu_enabled` is true-like.

### Public Cloud Assets

```python
public_count = truthy_count(findings["public_exposure"])
```

This counts rows where `public_exposure` is true-like.

### Outbound AI Traffic

```python
outbound_ai_count = truthy_count(findings["outbound_ai_traffic"])
```

This counts rows where outbound AI provider communication was detected.

## 14. Dashboard Charts

### Risk Severity Chart

The dashboard uses:

```python
findings["risk"].value_counts().reindex(RISK_ORDER, fill_value=0)
```

This counts findings per risk level and keeps the order:

1. Critical
2. High
3. Medium
4. Low

### Service Breakdown Chart

The dashboard uses:

```python
findings["detected_service"].value_counts()
```

This shows which AI services appear most often.

### Exposure Categories Chart

The dashboard uses:

```python
findings["exposure_category"].value_counts()
```

This shows the distribution of exposure types.

### Cloud Regions Chart

The dashboard filters rows where `region` is not empty and counts region values.

This shows where cloud AI assets are simulated.

### AI Provider Communication Chart

The dashboard filters rows where `ai_provider` is not empty and counts provider names.

This shows outbound communication to providers such as:

- OpenAI
- Anthropic
- HuggingFace
- Replicate
- Cohere

### Telemetry Sources Chart

The dashboard filters rows where `telemetry_source` is not empty and counts source values.

This shows whether detections came from:

- cloud inventory
- DNS logs
- flow logs
- activity logs
- correlation engine

## 15. Dashboard Tables

### Discovery Sources Table

This table counts `discovery_source` values.

It shows whether findings came from:

- Docker
- HTTP probes
- nmap
- Kubernetes
- cloud inventory
- cloud telemetry
- correlation engine

### Attack Surface Classification Table

This table counts `attack_surface_classification` values.

It groups findings into AI security concepts such as:

- Notebook Exposure
- Inference API Exposure
- AI Runtime Exposure
- Vector Database Exposure
- AI Provider Communication

### AI Asset Inventory Table

This table displays unique asset rows with:

- asset name
- source
- discovery source
- detected service
- service class
- attack surface
- image
- endpoint
- status
- cloud provider
- region
- subnet
- GPU status
- public exposure

### Cloud Telemetry Findings Table

This table filters findings where:

- `telemetry_source` is present, or
- `outbound_ai_traffic` is true

It displays:

- risk
- asset name
- AI provider
- provider type
- outbound traffic status
- telemetry source
- endpoint
- evidence
- recommendation

### Attack Path Visualization

The dashboard sorts findings by `risk_score` descending.

It displays the top five rows with:

- risk
- asset name
- detected service
- attack path

This gives a quick path-style view of likely security concern chains.

### AI-Specific Exposure Findings Table

This is the main detailed findings table.

It sorts rows by `risk_score` descending and displays:

- risk
- score
- service
- service class
- attack surface
- exposure
- source
- discovery source
- asset
- endpoint
- HTTP metadata
- cloud metadata
- AI provider metadata
- issue
- recommendation
- MITRE ATLAS fields

## 16. Generated Test Data

Running:

```powershell
python scanner.py --cloud-discovery --cloud-logs
```

generates:

- at least 10 cloud assets
- more than 20 telemetry events
- multiple AI provider detections
- mixed risk levels
- cloud asset findings
- outbound AI provider findings
- correlated attack path findings

The generated data feeds directly into `findings.csv`.

## 17. Why This Design Is Cloud-Native

The project does not rely only on open ports.

It also models:

- cloud compute inventory
- GPU workload metadata
- public/private exposure
- subnet and region context
- AI workload tags
- provider communication from logs
- telemetry source tracking
- correlation between asset inventory and outbound AI traffic

This mirrors the visibility approach used by enterprise AI security platforms, while staying lightweight and runnable on a local machine.
