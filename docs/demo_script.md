# 2-Minute Competition Judge Presentation Script

**Project Title**: SENTINEL-TLS — AI-Assisted Passive Network Forensic Framework for Email Infrastructure

---

## Stage Setup (0:00 - 0:15)
> **Presenter Action**: Open dashboard at `http://localhost:5173`. Point to the header bar, single-command run script, and offline status indicator.

**Speaker Pitch**:
> "Good morning judges! Email infrastructure is the #1 target for MITM downgrade attacks, weak ciphers, and expired certificates. Standard scanners actively probe servers, which alerts attackers and breaks offline compliance testing.
> 
> We created **SENTINEL-TLS** — an AI-assisted, 100% passive network forensic framework that reconstructs SMTP, IMAP, and POP3 streams from raw PCAP captures, scores cryptographic risk using explainable ML, and generates compliance readiness audits without decrypting a single byte of email content."

---

## Step 1: Clean Session Scenario (0:15 - 0:45)
> **Presenter Action**: Select **"Comprehensive Multi-Attack PCAP"** or **"Clean Baseline"** from the top scenario selector dropdown and click **"Run Scenario"**. Show the visual centerpiece **Traffic Flow Sankey Diagram**. Hover over the green flow path (`IMAP` ➔ `Implicit TLS` ➔ `TLS 1.3` ➔ `Modern AEAD`).

**Speaker Pitch**:
> "Look at our visual centerpiece — a 4-Stage Interactive Traffic Flow Architecture. Notice how clean traffic flows through green channels.
> 
> Let's inspect session `192.168.1.10:49152-192.168.1.100:993`. It negotiates TLS 1.3 with AEAD ciphers and an active 2048-bit RSA cert. Our ML engine assigns it a low risk score of **5.0/100**, marking it **SECURE**."

---

## Step 2: TLS 1.0 Downgrade Attack Scenario (0:45 - 1:15)
> **Presenter Action**: Filter session table by **"HIGH"** or search `10.0.0.15`. Click row to open the **Session Forensic Inspector Drawer**. Click Tab 1 (**AI SHAP Risk Attribution**).

**Speaker Pitch**:
> "Now look at session `10.0.0.15:52000-10.0.0.1:25`. The server offered TLS 1.3, but a MITM attacker forced a fallback to deprecated **TLS 1.0** with **3DES**.
> 
> Instead of a black-box score, our **SHAP Explainability Engine** breaks down exact feature impacts: TLS 1.0 adds **+30 risk points**, 3DES adds **+25 risk points**, bringing the risk score to **85.0/100 (HIGH RISK)**. 
> 
> Notice Tab 2 shows its passive **JA3 Client Fingerprint** (`e7d705a3286e...`), flagging anomalous client behavior without decryption."

---

## Step 3: Expired Certificate & STARTTLS Stripping (1:15 - 1:35)
> **Presenter Action**: Search `10.0.0.12` (STARTTLS stripping) or `10.0.0.22` (Expired Cert). Point out the **CRITICAL** badge and compliance violation mapping against **NIST SP 800-52 Rev. 2** and **PCI-DSS 4.0**.

**Speaker Pitch**:
> "Here, session `10.0.0.12` suffered a **STARTTLS Stripping Attack** where plain text injection suppressed encryption flags. Our Isolation Forest anomaly detector caught this zero-day flow and assigned a **100.0 CRITICAL** score, mapping violations directly to NIST SP 800-52 and PCI-DSS 4.0."

---

## Step 4: Live What-If Remediation Simulator & Report Export (1:35 - 2:00)
> **Presenter Action**: Open Tab 3 (**What-If Remediation Simulator**) for the high-risk session. Toggle switches:
> 1. Turn ON **"Upgrade Protocol to TLS 1.3"**
> 2. Turn ON **"Enable ECDHE Forward Secrecy"**
> 
> Show the live score counter dropping from **85.0 ➔ 12.0 (-73.0 pts)**.
> Finally, click **"Export Report"** ➔ **"PDF Document"** to show the printable audit PDF.

**Speaker Pitch**:
> "Here is our killer feature — the **What-If Remediation Simulator**. Administrators don't just want to know what's broken; they want to know the impact of fixing it.
> 
> Watch as I toggle 'Upgrade to TLS 1.3' and 'Enable ECDHE Forward Secrecy'. In real-time, our model re-infers the session feature vector, proving the risk score drops live from **85.0 to 12.0** — saving 73 risk points.
> 
> With one click on 'Export Report', we generate an executive PDF audit complete with compliance readiness percentages. All running 100% offline!"
