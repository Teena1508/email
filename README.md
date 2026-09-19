# SENTINEL-TLS

> **AI-Assisted Passive Network Forensic Framework for Email Infrastructure**  
> *Passive Cryptographic Posture Assessment, Explainable ML Risk Scoring, What-If Remediation Simulation, & Compliance Audit Mapping for SMTP, IMAP, and POP3.*

---

## Executive Summary & Core Innovations

Generic network diagnostic tools perform simple port scans or require active TLS proxy decryption. **SENTINEL-TLS** is designed specifically for security teams and competition judges requiring a **100% passive, offline-capable forensic system** that evaluates mail server cryptography directly from PCAP/PCAPNG packet streams.

### Key Differentiators & Innovations
1. **JA3 / JA3S Passive TLS Fingerprinting**: Identifies client and server TLS software stacks without traffic decryption, matching fingerprints against reference databases to flag malicious tools or outdated stacks.
2. **Synthetic PCAP Data Generator**: Generates 240+ labeled synthetic PCAP sessions across 8 attack categories (TLS downgrades, expired certs, weak ciphers, STARTTLS stripping, missing forward secrecy) for repeatable ML training and demo evaluation.
3. **Dual-Model ML Engine & SHAP Explainability**: Combines a Supervised Random Forest Classifier with an Unsupervised Isolation Forest Anomaly Detector (0-100 composite risk score) paired with SHAP TreeExplainer for plain-English feature attributions.
4. **Interactive What-If Remediation Simulator**: Allows security engineers to toggle proposed cryptographic fixes live and observe exact counterfactual risk score reductions.
5. **Automated Regulatory Compliance Mapping**: Maps findings directly to clauses in **NIST SP 800-52 Rev. 2**, **PCI-DSS 4.0**, **RFC 8314**, and **CIS Benchmarks** with PDF/HTML/JSON report generation.

---

## Quick Start & Setup Instructions

### Single-Command Offline Execution

To run the complete system locally (FastAPI backend + Vite React dashboard):

```bash
chmod +x run.sh
./run.sh
```

- **React Security Dashboard**: `http://localhost:5173`
- **FastAPI OpenAPI Documentation**: `http://localhost:8000/docs`

### Manual Component Setup

#### Backend (Python 3.10+)
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend (Node.js 18+)
```bash
cd frontend
npm install
npm run dev
```

---

## Machine Learning Architecture & Evaluation Metrics

### Supervised & Unsupervised Dual Model

| Model Component | Algorithm | Purpose | Output |
|---|---|---|---|
| **Supervised Classifier** | Random Forest (100 Trees) | Classifies known attack vectors | Severity probabilities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| **Unsupervised Anomaly Detector** | Isolation Forest (`contamination=0.1`) | Flags novel / zero-day misconfigurations | Continuous anomaly score (0.0 to 1.0) |
| **Explainability Engine** | SHAP (`TreeExplainer`) | Feature attribution & score justification | Per-feature risk impact points & English text |

### Evaluation Metrics (80/20 Test Split - 48 Holdout Sessions)

```text
               precision    recall  f1-score   support

         LOW     1.0000    1.0000    1.0000        12
      MEDIUM     1.0000    1.0000    1.0000        12
        HIGH     1.0000    1.0000    1.0000        12
    CRITICAL     1.0000    1.0000    1.0000        12

    accuracy                         1.0000        48
   macro avg     1.0000    1.0000    1.0000        48
weighted avg     1.0000    1.0000    1.0000        48
```

- **Confusion Matrix**: 100% diagonal precision across all 4 severity classes.
- **Zero-Day Anomaly Detection**: 100% detection rate on unencrypted STARTTLS stripping sessions (composite score forced to 100.0 CRITICAL).

---

## System Architecture

See detailed Mermaid flowcharts and component descriptions in [`docs/architecture_diagram.md`](docs/architecture_diagram.md).

```text
PCAP Ingestion ➔ Handshake/Cert Parser ➔ JA3 Fingerprinting ➔ Dual ML + SHAP ➔ Compliance Mapper ➔ Report Generator & Dashboard
```

---

## Current Scope & Honest Limitations

To ensure total transparency during competition evaluation:

1. **Passive Traffic Analysis (No Decryption)**: The framework analyzes ClientHello, ServerHello, and X.509 certificate records. It does **not** perform MITM decryption or inspect encrypted email body text.
2. **Synthetic Data Foundation**: The ML models are trained and evaluated on synthetic Scapy-generated PCAPs covering 8 structured categories. While highly effective for structural TLS misconfigurations, performance on enterprise breach corpora with custom TLS middleboxes requires further domain adaptation.
3. **Offline Certificate Validation**: Online Certificate Revocation List (CRL) and OCSP stapling checks are disabled to guarantee 100% offline local judging compatibility.
4. **Protocol Scope**: Currently specialized for email infrastructure protocols (**SMTP 25/465/587**, **IMAP 143/993**, **POP3 110/995**). General HTTPS web traffic is outside current scope.

---

## Presentation & Demo Script

For a step-by-step judge presentation walkthrough, refer to [`docs/demo_script.md`](docs/demo_script.md).
