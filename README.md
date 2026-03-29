# Traffic Signal Detection - Penetration Testing Setup

A YOLOv4-based traffic signal detection web application packaged for **security assessment and penetration testing**.

## Architecture

```
traffic-signal-detection/
├── app/                    # Flask web application
│   ├── main.py             # Routes and application factory
│   ├── config.py           # Configuration management
│   └── detector.py         # YOLOv4 inference wrapper
├── pentest/                # Penetration testing toolkit
│   ├── run_all_scans.sh    # Master scan orchestrator
│   ├── test_vulnerabilities.py  # Automated vulnerability tests
│   ├── test_api_fuzzing.py      # API endpoint fuzzing
│   └── reports/            # Generated scan reports
├── templates/              # Web UI
├── models/                 # YOLOv4 model files
├── .bandit.yaml            # Bandit SAST configuration
├── .semgrep.yml            # Semgrep custom rules
├── Dockerfile              # Container build
├── docker-compose.yml      # Full pentest environment
└── Epics_2023.ipynb        # Original Colab notebook
```

## Quick Start

### Option 1: Docker (recommended)

```bash
# Run app + pentest suite together
docker-compose up --build

# Run app only
docker-compose up --build app
```

### Option 2: Local

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

The application runs on **http://localhost:5000**.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web UI for image upload |
| `/health` | GET | Health check |
| `/api/detect` | POST | Upload image for detection (multipart form) |
| `/api/detect/url` | POST | Detect from image URL (JSON body) |
| `/api/model/info` | GET | Model configuration info |
| `/api/config` | GET/POST | View/modify runtime configuration |
| `/uploads/<path>` | GET | Serve uploaded files |

## Penetration Testing

### Automated Scans

Run the full scan suite:

```bash
bash pentest/run_all_scans.sh
```

This executes:

1. **Bandit** - Python static analysis (SAST)
2. **Safety** - Dependency vulnerability scanning
3. **Semgrep** - Custom security rules
4. **Vulnerability tests** - Automated active testing

### Individual Test Scripts

```bash
# Vulnerability tests against running app
python3 pentest/test_vulnerabilities.py --base-url http://localhost:5000

# API fuzzing
python3 pentest/test_api_fuzzing.py --base-url http://localhost:5000
```

### Static Analysis Only

```bash
# Bandit
bandit -r app/ -c .bandit.yaml

# Semgrep
semgrep --config .semgrep.yml app/
```

## Known Vulnerability Surface (Intentional for Testing)

The application includes **intentionally vulnerable endpoints** for penetration testing practice:

| Vulnerability | Location | OWASP Category |
|---------------|----------|----------------|
| **SSRF** | `/api/detect/url` - No URL validation | A10:2021 Server-Side Request Forgery |
| **Path Traversal** | `/uploads/<path>` - Unsanitized path | A01:2021 Broken Access Control |
| **Config Exposure** | `/api/config` GET - Leaks secrets | A01:2021 Broken Access Control |
| **Config Manipulation** | `/api/config` POST - Runtime changes | A01:2021 Broken Access Control |
| **Hardcoded Secret** | `config.py` - Default SECRET_KEY | A02:2021 Cryptographic Failures |
| **Debug Mode** | `run.py` - Flask debug enabled | A05:2021 Security Misconfiguration |
| **Missing Security Headers** | No CSP, HSTS, X-Frame-Options | A05:2021 Security Misconfiguration |
| **No Rate Limiting** | All endpoints open | A04:2021 Insecure Design |
| **No Authentication** | API endpoints unauthenticated | A07:2021 Identification Failures |
| **Error Info Leakage** | Stack traces in debug mode | A05:2021 Security Misconfiguration |
| **Unrestricted Upload** | Extension check only, no content validation | A04:2021 Insecure Design |

## Pentest Checklist

### Reconnaissance
- [ ] Enumerate all endpoints and HTTP methods
- [ ] Identify technology stack from headers and responses
- [ ] Check for hidden endpoints (/admin, /debug, /console, /.env)
- [ ] Review API responses for information leakage

### Authentication & Authorization
- [ ] Verify no authentication on sensitive endpoints
- [ ] Test for horizontal/vertical privilege escalation
- [ ] Check session management (if implemented)

### Input Validation
- [ ] Test file upload with malicious file types
- [ ] Test URL parameter for SSRF
- [ ] Test path traversal on file serving endpoint
- [ ] Fuzz all JSON inputs with unexpected types
- [ ] Test for command injection via filenames

### Configuration & Deployment
- [ ] Check for hardcoded credentials
- [ ] Verify debug mode is disabled in production
- [ ] Check for exposed configuration endpoints
- [ ] Verify proper error handling (no stack traces)
- [ ] Check TLS configuration

### Security Headers
- [ ] Content-Security-Policy
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Strict-Transport-Security
- [ ] Referrer-Policy
- [ ] Permissions-Policy

### Business Logic
- [ ] Test detection with adversarial images
- [ ] Test model theft via model info endpoint
- [ ] Test resource exhaustion with large/many uploads
- [ ] Test rate limiting on all endpoints

## Reports

After running the pentest suite, reports are generated in `pentest/reports/`:

- `bandit_report.json` / `.txt` - Static analysis findings
- `safety_report.json` - Dependency vulnerabilities
- `semgrep_report.json` / `.txt` - Custom rule matches
- `vuln_test_report.json` / `.txt` - Active vulnerability test results
- `fuzz_report.json` - API fuzzing results

## Model Setup

The application runs in **stub mode** without model weights. To enable real detection:

1. Download YOLOv4 custom weights trained on traffic signals
2. Place `yolov4-custom_1000.weights` in `models/`
3. Place `yolov4-custom.cfg` in `models/`
4. Update `models/classes.names` with your class labels
