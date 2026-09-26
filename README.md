# Codebase Doctor 🩺

> **Production-grade, zero-execution static analysis and health scoring system for public Python repositories.**

Codebase Doctor is a developer and security engineering tool that safely shallow-clones GitHub repositories into isolated temporary workspaces, performs deep static analysis, dependency vulnerability scanning, AST-based import graph and coupling analysis, calculates deterministic health scores across six dimensions, and optionally produces AI diagnoses and export-only patch proposals using an OpenAI-compatible LLM.

## 🎥 Demo

[▶️ Watch the Codebase Doctor Launch Demo](./demo.mp4)

## ✨ Highlights

* 🔐 **Zero-execution analysis** of untrusted repositories
* 🛡️ **SSRF, filesystem, subprocess, and secret-redaction safeguards**
* 🔎 **Ruff, Bandit, Semgrep, pip-audit, and AST analysis**
* 🏗️ **Import-graph and circular-dependency analysis**
* 📊 **Deterministic six-dimensional health scoring**
* 🤖 **Optional LLM-powered diagnosis**
* 🩹 **Export-only AI patch proposals**
* 🧪 **28-test verification suite**

---

## 🔒 Non-Negotiable Security Model

Codebase Doctor treats the scanned repository strictly as **untrusted input**.

### 1. Zero Untrusted Code Execution

* Never runs repository Python code, test suites, or setup scripts (`setup.py`, `pyproject.toml`, build hooks).
* Never executes `pip install` from repository manifests.
* Never executes shell scripts or README instructions provided by scanned repositories.
* Analysis executes solely using trusted analyzer binaries installed in our isolated environment (`ruff`, `bandit`, `semgrep`, `pip-audit`, Python AST/NetworkX).

### 2. Subprocess Isolation

* Subprocesses use explicit argument arrays (`shell=False`).
* `cwd` is locked to the cloned workspace root.
* Enforces strict execution timeouts (default 60s) with process group termination.
* Captures and truncates stdout/stderr.

### 3. SSRF & GitHub URL Allowlisting

* Accepts only HTTPS URLs targeting `github.com` or `www.github.com`.
* Rejects IP addresses (IPv4, IPv6, localhost, `127.0.0.1`, `0.0.0.0`, private RFC1918 subnets).
* Rejects credentials (`user:pass@`), custom ports, directory traversal tokens, and non-HTTPS schemes.

### 4. Filesystem & Clone Guards

* Enforces maximum clone size (default 50 MB), file count (default 2000 files), and single-file size limits.
* Blocks and skips symlinks that escape the isolated workspace root.

### 5. Secret Redaction

* Redacts high-entropy API keys and sensitive credentials including OpenAI, AWS, GitHub, and Slack tokens, private keys, passwords, and bearer tokens before persistence, API responses, or AI evidence packing.

### 6. No Automatic Patch Application

* The application **never modifies the scanned repository**.
* AI generates patch proposals as unified diffs that can only be reviewed and exported manually.

---

## 🏗️ System Architecture

```text
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

### Analysis Pipeline

```text
GitHub Repository URL
        │
        ▼
URL Validation & SSRF Protection
        │
        ▼
Safe Shallow Clone
        │
        ▼
Filesystem / Size / Symlink Guards
        │
        ▼
Repository Inventory
        │
        ├───────────────┐
        │               │
        ▼               ▼
 Static Analysis     Dependency Analysis
        │               │
        ├───────────────┤
        │
        ▼
AST Import Graph & Coupling Analysis
        │
        ▼
Normalized Findings
        │
        ▼
Deterministic Health Scoring
        │
        ├───────────────┐
        │               │
        ▼               ▼
 Dashboard        Capped Evidence Pack
                        │
                        ▼
                 Optional LLM Layer
                        │
                 ┌──────┴──────┐
                 ▼             ▼
              Diagnosis    Patch Proposal
                              │
                              ▼
                       Manual Export Only
```

---

## 📊 Deterministic Health Scoring

Every repository receives an auditable health score starting at **100.0** across six dimensions:

| Dimension           | Weight | Primary Data Sources & Analyzers                                       |
| ------------------- | :----: | ---------------------------------------------------------------------- |
| **Security**        |  `25%` | Bandit security scan, Semgrep injection/CORS rules, high-severity CVEs |
| **Code Quality**    |  `20%` | Ruff lint & bug rules, AST bug heuristics                              |
| **Architecture**    |  `15%` | AST import graph, circular dependency cycles, high-coupling hubs       |
| **Dependencies**    |  `15%` | `requirements.txt` manifests, unpinned packages, pip-audit CVEs        |
| **Maintainability** |  `15%` | Dead code, unused imports (`ruff:F401`), uncalled internal functions   |
| **Performance**     |  `10%` | Static performance rules (neutral 100 if no static findings detected)  |

### Penalty Deductions

* **Critical Finding:** `-20` points
* **High Severity:** `-8` points
* **Medium Severity:** `-3` points
* **Low Severity:** `-1` point
* **Floor:** All dimensions are strictly floored at `0.0`.

### Formula

$$
\text{Overall Score} =
0.25(\text{Security}) +
0.20(\text{CodeQuality}) +
0.15(\text{Architecture}) +
0.15(\text{Dependencies}) +
0.15(\text{Maintainability}) +
0.10(\text{Performance})
$$

> **Audit Guarantee:** Every deduction links to a specific finding rule ID and line number, allowing a reviewer to manually recompute and verify every score.

---

## 🔍 Static Analysis

Codebase Doctor combines multiple analysis techniques rather than relying on a single linter.

### Ruff

Used for:

* Python linting
* Bug-pattern detection
* Unused imports
* Code-quality findings

### Bandit

Used for:

* Python security checks
* Dangerous API usage
* Common insecure coding patterns

### Semgrep

Used for:

* Security-focused pattern matching
* Injection-related patterns
* CORS-related rules
* Custom security rules

### pip-audit

Used for:

* Dependency vulnerability detection
* Known package vulnerabilities
* Dependency audit findings

### Python AST

Used for:

* Import graph construction
* Dependency relationships
* Structural heuristics
* Architecture analysis
* Maintainability heuristics

### NetworkX

Used to analyze the resulting import graph for:

* Circular dependencies
* High-coupling modules
* Graph relationships

---

## 🏗️ Architecture Analysis

The architecture analyzer parses Python source using the Python AST rather than executing modules.

It builds an import graph representing relationships between modules and uses graph analysis to identify:

* Circular dependencies
* Highly connected modules
* Import relationships
* Potential architectural coupling

Because the source is parsed rather than imported, the architecture analysis does not require executing repository code.

---

## 🤖 AI Analysis Layer

AI functionality is **optional**.

The application remains usable for static analysis and deterministic scoring without an LLM configured.

When enabled, the AI layer receives a **capped and redacted evidence pack** rather than unrestricted repository contents.

### Evidence Pipeline

```text
Findings
   │
   ▼
Normalize & Deduplicate
   │
   ▼
Prioritize Relevant Evidence
   │
   ▼
Apply Secret Redaction
   │
   ▼
Cap Evidence Size
   │
   ▼
LLM
```

The evidence pack is constrained to approximately **32–64 KB** and is redacted before being provided to the model.

### AI Diagnosis

The diagnosis endpoint generates a structured analysis based on:

* Static findings
* Severity
* Analyzer information
* Source locations
* Architecture information
* Dependency findings
* Deterministic scores

### AI Patch Proposals

AI-generated fixes are represented as **unified diff proposals**.

The application does **not** automatically apply these patches.

The intended workflow is:

```text
Finding
   ↓
AI Diagnosis
   ↓
Patch Proposal
   ↓
Human Review
   ↓
Manual Export
   ↓
Developer Applies Patch
```

This keeps repository modification outside the application's trust boundary.

---

## 🛡️ Security Boundaries

The system is designed around several explicit trust boundaries.

### Untrusted Repository

The scanned repository may contain:

* Malicious Python code
* Malicious setup/build instructions
* Symlinks
* Huge files
* Large numbers of files
* Sensitive-looking strings
* Malformed source files

The repository is therefore never treated as executable application code.

### Trusted Analyzer Environment

Only the application's trusted analysis tools are executed:

```text
ruff
bandit
semgrep
pip-audit
Python AST
NetworkX
```

Analyzer subprocesses are controlled through explicit argument arrays and timeouts.

### AI Boundary

Only the processed evidence pack crosses into the optional LLM layer.

The evidence is:

1. Normalized
2. Redacted
3. Size-capped
4. Sent through the configured OpenAI-compatible endpoint

---

## 🛠️ Technology Stack

### Backend

* Python 3.12
* FastAPI
* SQLAlchemy
* SQLite
* Pydantic v2
* Uvicorn
* NetworkX
* HTTPX

### Static Analysis

* Ruff
* Bandit
* Semgrep
* pip-audit
* Python AST

### Frontend

* React 18
* TypeScript
* Vite
* Tailwind CSS
* Recharts
* Monaco Editor (`@monaco-editor/react`)
* Lucide React

### AI

* Pluggable OpenAI-compatible chat completion API
* `LLM_BASE_URL`
* `LLM_API_KEY`
* `LLM_MODEL`

---

## 🚀 Quick Start & Local Setup

### Prerequisites

* Python 3.11+
* Node.js 18+ and npm
* Git

### 1. Backend Setup

From the project root:

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment.

**Windows:**

```bash
.venv\Scripts\activate
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 2. Frontend Setup

From the project root:

```bash
cd frontend
npm install
```

Run the development server:

```bash
npm run dev
```

### 3. Environment Configuration

Copy `.env.example` to `.env` in the project root.

**Windows PowerShell:**

```powershell
Copy-Item .env.example .env
```

**Linux/macOS:**

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

From the project root with the virtual environment activated:

```bash
backend\.venv\Scripts\uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### Start Frontend Server

From the project root:

```bash
cd frontend
npm run dev
```

Open:

```text
http://localhost:5173
```

---

## 🧪 Running Automated Tests

Run the complete verification suite:

```bash
backend\.venv\Scripts\pytest.exe -v
```

The current suite contains **28 tests** covering:

* Unit tests
* Security tests
* Scoring tests
* Fixture pipeline tests
* API tests

---

## 📡 API Overview

| Method | Endpoint                       | Description                                                     |
| ------ | ------------------------------ | --------------------------------------------------------------- |
| `GET`  | `/health`                      | Application health check (`{"status": "ok"}`)                   |
| `POST` | `/api/scans`                   | Submit repository URL for analysis (`202 Accepted`)             |
| `GET`  | `/api/scans`                   | List recent scans                                               |
| `GET`  | `/api/scans/{id}`              | Scan status and repository inventory metadata                   |
| `GET`  | `/api/scans/{id}/findings`     | Filterable findings (`?category=...&severity=...&analyzer=...`) |
| `GET`  | `/api/scans/{id}/architecture` | Import graph, circular dependencies, and hub metrics            |
| `GET`  | `/api/scans/{id}/score`        | Six dimension scores and complete auditable breakdown           |
| `POST` | `/api/scans/{id}/ai/diagnose`  | Generate structured AI diagnosis from capped evidence pack      |
| `POST` | `/api/scans/{id}/ai/fixes`     | Generate export-only patch proposals                            |
| `GET`  | `/api/scans/{id}/ai`           | Retrieve persisted AI reports and patches                       |

---

## 📁 Project Structure

```text
CODEBASE-DOCTOR/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── analyzers/
│   │   ├── architecture/
│   │   ├── scoring/
│   │   ├── security/
│   │   └── ...
│   │
│   ├── tests/
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── rules/
│   └── semgrep/
│
├── tests/
│
├── .env.example
├── .gitignore
├── README.md
├── codebase_doctor.pdf
├── codebase_doctor_plan.pdf
└── demo.mp4
```

> The exact internal module structure may evolve as the project develops.

---

## 📈 Example Analysis Flow

A typical scan follows this sequence:

```text
1. Submit GitHub repository URL
              ↓
2. Validate URL and reject unsafe targets
              ↓
3. Shallow-clone repository
              ↓
4. Apply clone, file-count, size and symlink guards
              ↓
5. Inventory repository contents
              ↓
6. Run trusted static analyzers
              ↓
7. Parse Python files using AST
              ↓
8. Build import graph
              ↓
9. Detect cycles and coupling
              ↓
10. Normalize and deduplicate findings
              ↓
11. Calculate six health dimensions
              ↓
12. Calculate weighted overall score
              ↓
13. Persist scan results
              ↓
14. Display findings and architecture
              ↓
15. Optionally generate AI diagnosis
              ↓
16. Optionally generate export-only patch proposals
```

---

## ⚠️ Limitations & Disclaimers

### 1. Static Analysis Is Not Runtime Proof

Static analyzers cannot prove runtime safety or behavior. False positives and false negatives can occur.

A repository can pass static checks and still contain runtime bugs or vulnerabilities.

### 2. Heuristics Are Heuristics

Findings marked with `heuristic:` report probable issues based on static patterns.

Examples include:

* Possible `None` dereferences
* Infinite-loop patterns
* Uncalled internal functions
* Other structural maintainability indicators

These findings do not guarantee runtime certainty.

### 3. Python Deep Analysis Focus

Version 1 performs deep static analysis, AST import graph building, and dependency auditing primarily on Python codebases.

Non-Python files are cataloged in the repository inventory but are not analyzed with the same depth.

### 4. Dependency Analysis Limitations

Dependency auditing depends on the manifests and dependency information available within the repository.

Indirect or dynamically resolved dependencies may not always be fully represented.

### 5. AI Output Requires Human Review

AI-generated diagnoses and patch proposals may contain errors.

Patch proposals must be reviewed by a human developer before being applied to a source repository.

### 6. Export Only

Codebase Doctor does not automatically modify scanned repositories.

AI-generated patches are provided as exportable unified diffs for manual review and application.

---

## 🔐 Security Philosophy

Codebase Doctor follows a simple principle:

> **Analyze untrusted code without executing it.**

The system separates repository content from the trusted analyzer environment and applies security controls before, during, and after analysis.

The goal is not to claim that static analysis can eliminate all software risk. The goal is to make repository analysis **repeatable, auditable, bounded, and safer by design**.

---

## 📜 Project Status

**Codebase Doctor v1**

Current focus:

* Zero-execution repository analysis
* Security-focused static analysis
* Dependency auditing
* Import architecture analysis
* Deterministic health scoring
* Evidence normalization and redaction
* Optional LLM diagnosis
* Export-only AI patch proposals
* Automated security and API testing

The project is designed as a foundation for further analysis rules, additional language support, richer architectural metrics, and expanded developer workflows.
