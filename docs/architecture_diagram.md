# System Architecture & AI/ML Pipeline Diagram

The **SENTINEL-TLS** framework operates as an offline, passive network forensic pipeline for evaluating email infrastructure cryptographic posture (SMTP, IMAP, POP3) without inspecting or decrypting email payloads.

```mermaid
flowchart TD
    subgraph INGESTION["1. PCAP Stream Reconstruction Engine"]
        A[Raw PCAP / PCAPNG Upload] --> B[Scapy / PyShark TCP Stream Assembler]
        B --> C[Banner & Port Protocol Classifier\nSMTP 25/465/587, IMAP 143/993, POP3 110/995]
        C --> D[STARTTLS / Implicit TLS State Extractor]
        D --> E[Reconstructed EmailSession Struct]
    end

    subgraph TLS_ANALYSIS["2. Cryptographic Handshake & Cert Parser"]
        E --> F[ClientHello & ServerHello Byte Parser]
        F --> G[JA3 & JA3S Passive Fingerprint Generator]
        G --> H[Known-Bad / Malicious Fingerprint DB]
        F --> I[X.509 Certificate Chain Extractor]
        I --> J[Cert Validator\nExpiry, Key Length, Signature Alg]
        F --> K[Finding Classifier & Rule Engine]
        K --> L[CryptoAssessment Struct]
    end

    subgraph ML_ENGINE["3. AI / ML Risk Scoring & Explainability Engine"]
        L --> M[Numerical & Categorical Feature Extractor\n11-Dimensional Vector X]
        
        subgraph AI_MODELS["Dual-Model Risk Predictor"]
            M --> N["Supervised Random Forest Classifier\n(Predicts LOW, MEDIUM, HIGH, CRITICAL)"]
            M --> O["Unsupervised Isolation Forest\n(Zero-Day Anomaly Detection Score)"]
            N --> P[Composite Risk Score Formula\n0.65 * Supervised + 0.35 * Anomaly]
            O --> P
        end

        P --> Q["SHAP (TreeExplainer) Risk Attribution\n(Calculates per-feature SHAP impact points & English explanations)"]
        Q --> R[RiskPrediction Struct]
    end

    subgraph COMPLIANCE["4. Compliance Mapping Engine"]
        L --> S[Regulatory Rules Table\nNIST SP 800-52, PCI-DSS 4.0, RFC 8314, CIS]
        S --> T[ComplianceSummary Struct\nPer-Framework Readiness %]
    end

    subgraph SIMULATOR["5. What-If Remediation Simulator"]
        R --> U[Fix Selector: upgrade_tls13, enable_ecdhe, renew_cert]
        U --> V[Vector Mutation & Re-Inference]
        V --> W[Before vs. After Delta & Step Breakdown]
    end

    subgraph REPORTING_UI["6. Reporting & Dashboard UI"]
        R --> X[Report Generator Engine]
        T --> X
        X --> Y["Structured Exports\n(JSON, Jinja2 HTML, xhtml2pdf PDF)"]
        X --> Z["React Security Dashboard\n(Sankey Flow, SHAP Chart, Session Table, Live Simulator)"]
    end
```

## AI / ML Application Callouts

1. **Supervised Random Forest Classifier**
   - **Input**: 11-dimensional feature vector extracted from session handshake metadata.
   - **Output**: Multi-class severity prediction (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with confidence probabilities.

2. **Unsupervised Isolation Forest Anomaly Detector**
   - **Input**: Feature vector of active mail sessions.
   - **Output**: Continuous anomaly score (0.0 to 1.0) flagging zero-day misconfigurations or uncommon TLS stacks that bypass rule tables.

3. **SHAP (SHapley Additive exPlanations) TreeExplainer**
   - **Input**: Random Forest model + session feature vector.
   - **Output**: Exact feature attribution points and natural-language risk explanations.

4. **Predictive What-If Remediation Simulator**
   - **Input**: Active session vector + toggled security fixes.
   - **Output**: Real-time counterfactual model re-inference predicting risk score reduction points.
