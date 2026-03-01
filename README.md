
# 🧠 NLP-Driven Cyber Threat Intelligence Analyzer (CTI)

A **blue-team–focused, ethical Cyber Threat Intelligence (CTI) analysis platform** that combines rule-based detection, MITRE ATT&CK mapping, corpus-enriched reasoning, and AI-powered defensive intelligence modeling into a structured and explainable workflow.

This tool is designed for:

- 🛡️ Security Architects  
- 🔵 Blue Teams  
- 📊 SOC Analysts  
- 🔍 Threat Intelligence Analysts  
- 🧪 AppSec Engineers  
- 📋 GRC & Audit Teams  

It provides structured, defensive-only intelligence without exploit generation, payload construction, or offensive automation.

---

# 📊 Project Overview

The NLP-Driven Cyber Threat Intelligence Analyzer integrates:

- Rule-based threat signal detection
- Line-level evidence extraction
- MITRE ATT&CK tactical mapping
- AI-powered structured defensive reasoning
- Risk scoring & severity modeling
- Optional corpus-enriched knowledge grounding
- Visual dashboard + downloadable structured reports

### 🔎 Core Architecture

Rule-Based Detection  
+ Structured LLM Reasoning  
+ Optional Corpus Enrichment  
+ Defensive-Only Constraints  

The system is modular, explainable, and safe for enterprise defensive environments.

---

# 🔍 Key Capabilities

## 🧠 1️⃣ Advanced Threat Signal Detection

- Detects 30+ security signal categories
- Covers:
  - Authentication weaknesses
  - Credential exposure
  - Cloud misconfiguration
  - API abuse
  - Container risks
  - Data exposure
  - Phishing indicators
  - Malware signals
  - Privilege escalation risks
  - Network exposure
- Extracts matched source lines for analyst validation

---

## 🗺 2️⃣ MITRE ATT&CK Mapping

Signals are automatically mapped to relevant MITRE ATT&CK tactics such as:

- TA0001 – Initial Access
- TA0006 – Credential Access
- TA0008 – Lateral Movement
- TA0009 – Collection
- TA0010 – Exfiltration

This enables standardized reporting aligned with the framework maintained by the MITRE Corporation.

---

## 📈 3️⃣ Risk Scoring Engine

- Dynamic risk calculation (0–10 scale)
- Severity labeling:
  - LOW
  - MEDIUM
  - HIGH
- Per-signal risk modeling
- Overall intelligence confidence indicator

Designed for audit-friendly documentation and executive reporting.

---

## 📚 4️⃣ Flexible AI Knowledge Modes

The analyzer supports four knowledge configurations:

### 🔹 Option 1 — Independent AI Mode
- No corpus selected
- AI reasons using pretrained intelligence
- Best for quick research or lightweight assessments

### 🔹 Option 2 — Internal Corpus Mode
- Uses built-in defensive knowledge directory
- Organization-controlled documentation
- AI enriches reasoning using corpus
- Still reasons independently

### 🔹 Option 3 — Uploaded Corpus ZIP
- Upload custom `.zip` containing `.txt` knowledge files
- Ideal for:
  - Client documentation
  - Audit frameworks
  - Project-specific knowledge

### 🔹 Option 4 — Multi-Corpus ZIP Upload
- Upload multiple corpora bundled in ZIP
- All files extracted and merged
- AI receives unified defensive knowledge context

---

## 🧠 Important Design Principle

This tool does **NOT** enforce strict grounding.

If corpus is selected:
- AI uses corpus as enrichment
- AI may expand, refine, or challenge corpus knowledge
- Independent reasoning remains active

Corpus = Supportive Knowledge  
AI = Independent Defensive Analyst

---

# 📊 Output & Reporting

The analyzer generates:

- Structured on-screen analysis
- Per-signal breakdown:
  - Threat Significance
  - Attacker Objectives
  - Attack Chain Potential
  - MITRE Tactical Relevance
  - Early Warning Indicators
  - Defensive Priorities
  - Strategic Security Improvements
- Downloadable `.txt` intelligence report
- Visual risk dashboard

Suitable for:

- SOC documentation
- Risk assessments
- Architecture reviews
- Incident record enrichment
- Audit preparation

---

# 🔄 Defensive Intelligence Workflow

The analyzer provides:

1️⃣ Threat Signal Awareness  
2️⃣ Tactical Mapping Awareness  
3️⃣ Weaponization Risk Projection (Strategic, not exploitative)  
4️⃣ Defensive Hardening Guidance  

Structured. Explainable. Defensive.

---

# 🚀 Getting Started

## Requirements

- Python 3.9+
- Streamlit
- huggingface_hub
- matplotlib

Install dependencies:

```bash
pip install streamlit huggingface_hub matplotlib
```

---

## 🔐 Environment Variable (Required)

Never hard-code API tokens.

### macOS / Linux

```bash
export HF_TOKEN=hf_xxxxxxxxxxxxx
```

### Windows

```bash
setx HF_TOKEN hf_xxxxxxxxxxxxx
```

---

## ▶ Running the Tool

```bash
streamlit run cti_analyzer.py
```

Before running:

- Ensure corpus directory exists (if using internal corpus)
- Or upload corpus ZIP files via UI
- Upload recon / scan `.txt` file
- Click **Run Advanced CTI Analysis**

---

# 🔒 Ethical & Defensive Scope

This toolkit is:

- ✅ Defensive-only
- ✅ Ethical by design
- ✅ Enterprise-safe
- ✅ Audit-friendly
- ✅ No exploit logic
- ✅ No payload crafting
- ✅ No attack automation

AI reasoning is strictly constrained to:

- Risk analysis
- Strategic modeling
- Threat understanding
- Defensive mitigation guidance

---

# 🧩 Extensibility

The platform is modular and extensible:

- Add new detection rules
- Expand threat signal categories
- Add custom MITRE mappings
- Improve risk scoring models
- Expand corpus knowledge base
- Integrate with SOC workflows
- Connect to SIEM or log pipelines
- Add time-series tracking

Pull requests focused on **defensive improvements** are welcome.

---

# 🧭 Intended Audience

- Blue Team Analysts
- SOC Engineers
- Threat Intelligence Analysts
- Application Security Engineers
- Security Architects
- GRC & Audit Teams
- Defensive Security Researchers

---

# ⚠ Disclaimer

This toolkit is intended solely for:

- Defensive cybersecurity analysis
- Authorized testing
- Security research
- Educational purposes

Use only on systems you own or have explicit authorization to analyze.

The author is not responsible for misuse.

---

# 👤 Author

**Khin La Pyae Woon**  
AI-Enhanced Ethical Hacking | Cybersecurity | Digital Forensic | Analysis | Development  

🌐 Portfolio:  
https://khinlapyaewoon-cyberdev.vercel.app  

🔗 LinkedIn:  
https://www.linkedin.com/in/khin-la-pyae-woon-ba59183a2  

💬 WhatsApp:  
https://wa.me/qr/MJYX74CQ5VA4D1  

---

🛡️ *Defensive security is not about knowing every exploit — it’s about understanding risk, intent, and control.*
