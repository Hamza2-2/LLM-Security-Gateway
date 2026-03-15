# Presidio-Based LLM Security Mini-Gateway

A modular security gateway that protects LLM-based systems from prompt injection, jailbreak attacks, and sensitive information leakage using Microsoft Presidio and configurable policy rules.

## Architecture

```
User Input → Injection Detection → Presidio PII Analyzer → Policy Decision → Output
                 (keyword scoring)     (custom recognizers)     (Allow/Mask/Block)
```

## Quick Start (Windows)

```
1. Double-click  setup\setup.bat       (one-time install)
2. Double-click  gui\run_gui.bat       (launch GUI)
```

## Project Structure

```
llm-security-gateway/
│
├── core/                          # Core pipeline modules
│   ├── __init__.py
│   ├── config.py                  # All configurable thresholds
│   ├── injection_detector.py      # Prompt injection scoring
│   ├── presidio_engine.py         # Presidio + custom recognizers
│   ├── policy_engine.py           # Allow / Mask / Block decisions
│   └── gateway.py                 # Shared scan() function
│
├── gui/                           # Tkinter GUI
│   ├── app.py                     # GUI application
│   └── run_gui.bat                # Launch GUI
│
├── server/                        # Flask API server
│   ├── app.py                     # Flask endpoints
│   └── run_server.bat             # Launch server
│
├── evaluation/                    # Testing & evaluation
│   ├── evaluate.py                # Full evaluation (5 tables)
│   ├── quick_test.py              # Quick 9-test check
│   ├── run_eval.bat               # Run full evaluation
│   └── run_test.bat               # Run quick tests
│
├── setup/                         # Installation
│   ├── setup.bat                  # One-time setup script
│   └── requirements.txt           # Python dependencies
└── README.md
```

## Usage

### Option 1: Tkinter GUI (Recommended for testing/viva)
```
gui\run_gui.bat
```

### Option 2: Flask API Server
```
server\run_server.bat
```
Then in PowerShell:
```powershell
Invoke-RestMethod -Method POST -Uri http://localhost:5000/scan -ContentType "application/json" -Body '{"text": "My CNIC is 35201-1234567-1"}'
```

### Option 3: Quick Tests (terminal)
```
evaluation\run_test.bat
```

### Option 4: Full Evaluation (5 mandatory tables)
```
evaluation\run_eval.bat
```

## Manual Setup (if not using setup.bat)

```bash
pip install -r setup/requirements.txt
python -m spacy download en_core_web_lg
```

## Custom Presidio Recognizers

1. **PK_CNIC**: Pakistani CNIC numbers (`XXXXX-XXXXXXX-X`)
2. **API_KEY**: OpenAI (`sk-...`), AWS (`AKIA...`), generic keys
3. **INTERNAL_ID**: Employee (`EMP-XXXXXX`), Project (`PROJ-XXXX`), Department (`DEPT-XX-XXXX`)

## Configuration

All thresholds in `core/config.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `INJECTION_BLOCK_THRESHOLD` | 4 | Score to trigger BLOCK |
| `INJECTION_WARN_THRESHOLD` | 2 | Score to trigger WARN/MASK |
| `CONTEXT_BOOST` | 0.15 | Confidence boost from context |
| `ENABLED_ENTITIES` | 9 types | Which PII types to scan for |

## License

Academic project — Bahria University, Information Security (CEN-451)
