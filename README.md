# Traffic-Signal-Detection

A YOLOv4-based traffic signal detection system built on Google Colab with GPU acceleration using the darknet framework.

## Project Structure

```
.
├── Epics_2023.ipynb              # Main training & inference notebook (Colab)
├── 3rdparty/                     # Vendored C/C++ headers
│   ├── stb/include/              # stb image library headers
│   └── pthreads/include/         # POSIX threads headers (Win32)
├── pentest/                      # Penetration testing framework
│   ├── PENTEST_GUIDE.md          # Comprehensive pentest guide & checklist
│   ├── requirements.txt          # Security scanning dependencies
│   ├── configs/                  # Scanner configurations
│   │   ├── bandit.yaml           # Bandit static analysis config
│   │   └── semgrep-rules.yaml    # Custom semgrep security rules
│   ├── scripts/                  # Automated security test scripts
│   │   ├── run_all_tests.py      # Master test orchestrator
│   │   ├── static_analysis.py    # Code security scanner
│   │   ├── dependency_audit.py   # Dependency & supply-chain auditor
│   │   ├── ml_security_tests.py  # ML-specific security tests
│   │   └── notebook_hardening.py # Notebook hardening advisor
│   └── reports/                  # Generated scan reports (JSON)
└── README.md
```

## Security Testing

This project includes an automated penetration testing framework. See [`pentest/PENTEST_GUIDE.md`](pentest/PENTEST_GUIDE.md) for the full guide.

### Quick Start

```bash
pip install -r pentest/requirements.txt
python pentest/scripts/run_all_tests.py
```

### What Gets Tested

- **Static Analysis**: Hardcoded secrets, unsafe code patterns, shell injection risks
- **Dependency Audit**: Known CVEs, unpinned versions, supply-chain integrity
- **ML Security**: Adversarial robustness, data poisoning, model integrity, input validation
- **Notebook Hardening**: Cell-by-cell security recommendations
