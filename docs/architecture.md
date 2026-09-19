# System Architecture & Technical Design

## 1. Overview
The **AI-Assisted Passive Network Forensic Framework** is designed for offline, non-intrusive evaluation of email infrastructure security posture (SMTP, IMAP, POP3) from captured network traffic (`.pcap`/`.pcapng`).

## 2. Core Architecture Pipeline

```mermaid
flowchart TD
    subgraph Data Layer
        A[Raw PCAP File] -->|Offline Read| B[PyShark / Scapy Ingestion]
        S[Synthetic PCAP Generator] -->|Labeled Attack Scenarios| A
    end

    subgraph Forensic & Cryptographic Analysis Engine
        B --> C{Protocol Dissector}
        C -->|SMTP 25/587| D[STARTTLS / TLS Handshake Extractor]
        C -->|IMAP 143/993| D
        C -->|POP3 110/995| D
        
        D --> E[JA3 / JA3S Fingerprinter]
        D --> F[Cipher Suite & Protocol Audit]
        D --> G[X.509 Certificate Chain Parser]
    end

    subgraph Intelligence & Scoring Engine
        E & F & G --> H[Feature Extraction Matrix]
        H --> I[Scikit-Learn ML Risk Classifier]
        I --> J[SHAP Feature Attribution Explainer]
    end

    subgraph Reporting & Simulation Layer
        J --> K[Compliance Mapper\nNIST SP 800-52 | PCI-DSS 4.0 | RFC 8314 | CIS]
        J --> L[Remediation Simulator\nWhat-If Risk Recalculation]
    end

    subgraph Frontend Dashboard
        K & L --> M[React + Recharts Dashboard]
    end
```

## 3. Subsystem Breakdown

### 3.1 `ingestion/`
- Parses offline PCAP network captures using `pyshark` and `scapy`.
- Extracts TCP streams corresponding to email services (Ports 25, 465, 587 for SMTP; 143, 993 for IMAP; 110, 995 for POP3).

### 3.2 `tls_analysis/`
- **JA3/JA3S Fingerprinting**: Generates MD5 hashes of ClientHello / ServerHello parameters (SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, Elliptic Curve Formats) to identify known malware/anomalous clients without decrypting payloads.
- **STARTTLS Dissection**: Checks if plaintext connections are upgraded securely or exposed to stripping attacks.
- **Cryptographic Audit**: Evaluates TLS version (flagging TLS 1.0/1.1), cipher suites (forward secrecy, weak ciphers like RC4, 3DES, EXPORT), and X.509 certificate validity.

### 3.3 `ml/`
- Risk Scoring model (`scikit-learn`) producing normalized risk indices (0–100).
- `SHAP` explainability engine providing exact feature attribution vectors for every score.

### 3.4 `reporting/`
- Automatic compliance auditing against NIST SP 800-52 Rev 2, PCI-DSS 4.0 Requirement 4.2, RFC 8314 (Implicit TLS requirement), and CIS benchmarks.
- Remediation simulator for interactive what-if security impact analysis.
