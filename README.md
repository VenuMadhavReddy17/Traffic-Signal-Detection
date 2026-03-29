# Traffic-Signal-Detection

A traffic signal detection application using deep learning, with an integrated penetration testing and security assessment framework.

## Project Structure

```
.
├── Epics_2023.ipynb           # Main ML notebook (Google Colab)
├── 3rdparty/                  # Vendored C/C++ libraries
│   ├── stb/                   # stb image loading/writing
│   └── pthreads/              # Pthreads-win32 headers
├── pentest/                   # Security assessment framework
│   ├── runner.py              # Main pentest orchestrator
│   ├── report.py              # Report generation (text + JSON)
│   ├── config.yaml            # Scanner configuration
│   ├── requirements.txt       # Pentest dependencies
│   └── scanners/              # Security scanner modules
│       ├── base.py            # Base scanner class & data models
│       ├── notebook_scanner.py # Jupyter/Colab notebook security
│       ├── secret_scanner.py  # Credential & secret detection
│       ├── dependency_scanner.py # Dependency vulnerability checks
│       ├── ml_scanner.py      # ML/AI-specific security
│       └── code_scanner.py    # Static code analysis (C/C++/Python)
└── README.md
```

## Penetration Testing Framework

### Quick Start

```bash
# Install dependencies
pip install -r pentest/requirements.txt

# Run all security scanners
python -m pentest.runner

# Save reports to pentest/reports/
python -m pentest.runner --save

# JSON output only (for CI/CD integration)
python -m pentest.runner --json-only

# Scan a specific directory
python -m pentest.runner --target /path/to/scan

# Use custom config
python -m pentest.runner --config path/to/config.yaml
```

### Security Scanners

The framework includes five specialized scanners:

#### 1. Notebook Security Scanner
- Detects hardcoded credentials and API keys in notebook cells
- Identifies dangerous shell commands (`!sudo`, `!wget`, `!rm -rf`)
- Flags unsafe imports (pickle, subprocess, ctypes)
- Checks for leaked secrets in cell outputs
- Audits Colab metadata for information disclosure

#### 2. Secret Detection Scanner
- Scans all text files for leaked credentials
- Detects AWS keys, GitHub tokens, Slack tokens, JWTs
- Identifies hardcoded passwords and connection strings
- Finds private key material in committed files
- Auto-redacts findings in reports

#### 3. Dependency Vulnerability Scanner
- Extracts dependencies from requirements files and notebooks
- Checks for unpinned dependency versions
- Cross-references against known vulnerable package versions
- Integrates with `pip-audit` for comprehensive CVE checking

#### 4. ML/AI Security Scanner
- Detects unsafe model deserialization (pickle, torch.load, joblib)
- Identifies untrusted model download patterns
- Checks for training data leakage vectors
- Flags adversarial robustness concerns
- Audits ML supply chain risks

#### 5. Static Code Analysis Scanner
- Scans C/C++ headers for buffer overflow patterns (gets, strcpy, sprintf)
- Checks Python code for injection vulnerabilities (eval, exec, os.system)
- Validates include guards in header files
- Detects weak cryptographic patterns

### Report Formats

Reports are generated in two formats:

- **Text report**: Human-readable with severity-colored output and risk scoring
- **JSON report**: Machine-parseable for CI/CD pipeline integration

### Exit Codes

| Code | Meaning |
|------|---------|
| 0    | No critical or high findings |
| 1    | High severity findings detected |
| 2    | Critical severity findings detected |

### Configuration

Edit `pentest/config.yaml` to customize:
- Secret detection patterns
- ML security checks to enable/disable
- Notebook security rules
- Scan target directories and file patterns
- Report output formats and directory

### CI/CD Integration

```yaml
# Example GitHub Actions integration
security-scan:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: '3.11'
    - run: pip install -r pentest/requirements.txt
    - run: python -m pentest.runner --json-only --no-color > security-report.json
    - uses: actions/upload-artifact@v4
      with:
        name: security-report
        path: security-report.json
```
