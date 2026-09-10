# Codebase Doctor 🩺

> **Production-grade, zero-execution static analysis and health scoring system for public Python repositories.**

Codebase Doctor is a developer and security engineering tool that safely shallow-clones GitHub repositories into isolated temporary workspaces, performs deep static analysis, dependency vulnerability scanning, AST-based import graph and coupling analysis, calculates deterministic health scores across six dimensions, and optionally produces AI diagnoses and export-only patch proposals using an OpenAI-compatible LLM.

---

## 🔒 Non-Negotiable Security Model

Codebase Doctor treats the scanned repository strictly as **untrusted input**.

1. **Zero Untrusted Code Execution**:
   - Never runs repository Python code, test suites, or setup scripts (`setup.py`, `pyproject.toml`, build hooks).
   - Never executes `pip install` from repository manifests.
   - Never executes shell scripts or README instructions provided by scanned repositories.
   - Analysis executes solely using trusted analyzer binaries installed in our isolated environment (`ruff`, `bandit`, `semgrep`, `pip-audit`, Python AST/NetworkX).
2. **Subprocess Isolation**:
   - Subprocesses use explicit argument arrays (`shell=False`).
   - `cwd` is locked to the cloned workspace root.
   - Enforces strict execution timeouts (default 60s) with process group termination.
   - Captures and truncates stdout/stderr.
3. **SSRF & GitHub URL Allowlisting**:
   - Accepts only HTTPS URLs targeting `github.com` or `www.github.com`.
   - Rejects IP addresses (IPv4, IPv6, localhost, 127.0.0.1, 0.0.0.0, private RFC1918 subnets).
   - Rejects credentials (`user:pass@`), custom ports, directory traversal tokens, and non-HTTPS schemes.
4. **Filesystem & Clone Guards**:
   - Enforces maximum clone size (default 50 MB), file count (default 2000 files), and single-file size limits.
   - Blocks and skips symlinks that escape the isolated workspace root.
5. **Secret Redaction**:
   - Redacts high-entropy API keys (OpenAI, AWS, GitHub tokens, Slack tokens, private keys, passwords, bearer tokens) before persistence, API responses, or AI evidence packing.
6. **No Automatic Patch Application**:
   - The application **never modifies the scanned repository**.
   - AI generates patch proposals as unified diffs that can only be reviewed and exported manually.

---

## 🏗️ System Architecture

```
                                  ┌────────────────────────┐
                                  │   React + TypeScript   │
                                  │   Dark-First Dashboard │
                                  └───────────┬────────────┘
                                              │ HTTP / REST
                                  ┌───────────▼────────────┐
                                  │     FastAPI Backend    │
                                  └───────────┬────────────┘
                                              │
                      ┌───────────────────────┼───────────────────────┐
                      │                       │                       │
             ┌────────▼────────┐    ┌─────────▼────────┐    ┌─────────▼────────┐
             │ Safe Clone &    │    │ Static Analyzers │    │  Deterministic   │
             │ Path Isolation  │    │  (Fail-Soft)     │    │  Scoring Engine  │
             └────────┬────────┘    └─────────┬────────┘    └─────────┬────────┘
                      │                       │                       │
                      │             ┌─────────┴─────────┐             │
                      │             │ Ruff, Bandit,     │             │
                      │             │ Semgrep, AST,     │             │
                      │             │ pip-audit         │             │
                      │             └─────────┬─────────┘             │
                      │                       │                       │
                      └───────────────────────┼───────────────────────┘
                                              │
                                  ┌───────────▼────────────┐
                                  │ SQLite Database Store  │
                                  └───────────┬────────────┘
                                              │
                                  ┌───────────▼────────────┐
                                  │ Capped Evidence Pack   │
                                  │ (32-64 KB, Redacted)   │
                                  └───────────┬────────────┘
                                              │
                                  ┌───────────▼────────────┐
                                  │ Pluggable LLM Layer    │
                                  │ Validated Diagnoses &  │
                                  │ Export-Only Patches    │
                                  └────────────────────────┘
```

---

## 📊 Deterministic Health Scoring

Every repository receives an auditable health score starting at **100.0** across six dimensions:

| Dimension | Weight | Primary Data Sources & Analyzers |
|---|:---:|---|
| **Security** | `25%` | Bandit security scan, Semgrep injection/CORS rules, high-severity CVEs |
| **Code Quality** | `20%` | Ruff lint & bug rules, AST bug heuristics |
| **Architecture** | `15%` | AST import graph, circular dependency cycles, high-coupling hubs |
| **Dependencies** | `15%` | `requirements.txt` manifests, unpinned packages, pip-audit CVEs |
| **Maintainability**| `15%` | Dead code, unused imports (`ruff:F401`), uncalled internal functions |
| **Performance** | `10%` | Static performance rules (neutral 100 if no static findings detected) |

### Penalty Deductions
- **Critical Finding**: `-15` points
- **High Severity**: `-8` points
- **Medium Severity**: `-3` points
- **Low Severity**: `-1` points
- **Floor**: All dimensions are strictly floored at `0.0`.

### Formula
$$\text{Overall Score} = 0.25(\text{Security}) + 0.20(\text{CodeQuality}) + 0.15(\text{Architecture}) + 0.15(\text{Dependencies}) + 0.15(\text{Maintainability}) + 0.10(\text{Performance})$$

> **Audit Guarantee**: Every deduction links to a specific finding rule ID and line number, allowing a reviewer to manually recompute and verify every score.

---

## 🛠️ Technology Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy, SQLite, Pydantic v2, Uvicorn, NetworkX, HTTPX.
- **Analyzers**: Ruff, Bandit, Semgrep (with custom rules), pip-audit, Python AST.
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS, Recharts, Monaco Editor (`@monaco-editor/react`), Lucide React.
- **AI**: Pluggable OpenAI-compatible chat completion API (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`).

---

## 🚀 Quick Start & Local Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Git

### 1. Backend Setup

```bash
# In project root: C:\Users\ADMIN\engg\projects\CODEBASE
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Frontend Setup

```bash
# In project root
cd frontend

# Install node dependencies
npm install

# Build or run development server
npm run dev
```

### 3. Environment Configuration

Copy `.env.example` to `.env` in the root:

```bash
cp .env.example .env
```

Configuration variables:
```ini
DATABASE_URL=sqlite:///./data/codebase_doctor.db
HOST=127.0.0.1
PORT=8000
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Optional LLM Configuration
# The application works fully without an LLM configured!
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

---

## 🏃 Running Locally

### Start Backend Server
```bash
# From project root with venv activated
backend\.venv\Scripts\uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be accessible at: `http://127.0.0.1:8000/docs`

### Start Frontend Server
```bash
# From project root
cd frontend
npm run dev
```
Open browser at: `http://localhost:5173`

---

## 🧪 Running Automated Tests

Run the complete 28-test verification suite (unit tests, security tests, scoring tests, fixture pipeline tests, and API tests):

```bash
backend\.venv\Scripts\pytest.exe -v
```

---

## 📡 API Overview

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Application health check (`{"status": "ok"}`) |
| `POST` | `/api/scans` | Submit repository URL for analysis (`202 Accepted`) |
| `GET` | `/api/scans` | List recent scans |
| `GET` | `/api/scans/{id}` | Scan status and repository inventory metadata |
| `GET` | `/api/scans/{id}/findings` | Filterable findings (`?category=...&severity=...&analyzer=...`) |
| `GET` | `/api/scans/{id}/architecture` | Import graph, circular dependencies, and hub metrics |
| `GET` | `/api/scans/{id}/score` | 6 dimension scores and complete auditable breakdown |
| `POST` | `/api/scans/{id}/ai/diagnose` | Generate structured AI diagnosis from capped evidence pack |
| `POST` | `/api/scans/{id}/ai/fixes` | Generate export-only patch proposals |
| `GET` | `/api/scans/{id}/ai` | Retrieve persisted AI reports and patches |

---

## ⚠️ Limitations & Disclaimers

1. **Static Analysis is Not Runtime Proof**: Static analyzers cannot prove runtime safety or behavior. False positives or negatives can occur.
2. **Heuristics are Heuristic**: Findings marked with `heuristic:` (e.g. possible None dereferences, infinite loop patterns) report probable issues with static confidence estimates and do not guarantee runtime certainty.
3. **Python Deep Analysis Focus**: Version 1 performs deep static analysis, AST import graph building, and dependency auditing primarily on Python codebases. Non-Python files are cataloged in repository inventory.
4. **Export Only**: Patches proposed by AI must be reviewed by a human developer before applying to source repositories.
