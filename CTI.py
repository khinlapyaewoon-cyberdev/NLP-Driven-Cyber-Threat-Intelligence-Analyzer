#!/usr/bin/env python3
# ==================================================
# 🧠 Advanced NLP-Driven Cyber Threat Intelligence Analyzer
# Defensive | Ethical | Blue-Team Focused
# ==================================================

import os
import streamlit as st
import matplotlib.pyplot as plt
from huggingface_hub import InferenceClient
from datetime import datetime
import zipfile, tempfile

# ==================================================
# 🔐 CLEAR PROXIES
# ==================================================
for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
    os.environ[k] = ""

# ==================================================
# 🔐 HF CONFIG
# ==================================================
HF_TOKEN = "HF_TOKEN"
MODEL = "meta-llama/Llama-3.1-8B-Instruct"

if not HF_TOKEN:
    st.error("HF_TOKEN environment variable not set.")
    st.stop()

client = InferenceClient(model=MODEL, token=HF_TOKEN, timeout=180)

# ==================================================
# 🧠 EXTENDED THREAT SIGNALS FOR ANY PERSPECTIVE (Keywords can be added if need)
# ==================================================
THREAT_SIGNALS = {

    # Access & Authentication
    "Exposed Administrative Interface": ["/admin", "/dashboard", "/manage"],
    "Authentication Weakness": ["no authentication", "anonymous", "weak password"],
    "Credential Exposure": ["api_key", "password=", "token=", "secret="],

    # Network & Infrastructure
    "Open Network Services": ["open port", "0.0.0.0", "listening on"],
    "Unrestricted Internal Service": ["internal", "localhost exposed"],
    "Cloud Storage Exposure": ["s3 bucket", "public bucket", "blob storage"],

    # Software & Versioning
    "Outdated Software": ["deprecated", "end of life", "version 1."],
    "Legacy Protocol Usage": ["tls 1.0", "tls 1.1", "ssl v3"],

    # Application Security
    "Debug Artifact Exposure": ["stack trace", "traceback", "debug"],
    "Insecure Security Headers": ["missing security headers", "x-frame-options"],
    "CORS Misconfiguration": ["access-control-allow-origin", "credentials=true"],

    # Data Exposure
    "Metadata Disclosure": ["server:", "x-powered-by"],
    "Sensitive File Exposure": [".env", ".git", "backup.sql"],

    # Privilege & Access Control
    "Excessive Privilege Assignment": ["admin privileges", "root access"],
    "Improper Access Control": ["unauthorized access", "forbidden bypass"],

    # API & Microservices
    "Exposed API Endpoint": ["/api/", "/v1/", "/v2/"],
    "GraphQL Introspection Enabled": ["__schema", "__type"],

    # Social Engineering & Human Factors
    "Phishing Susceptibility": ["click here", "verify your account", "password reset link"],
    "Malicious Email Indicators": ["attachment.exe", "macro enabled", "urgent request"],

    # Malware & Persistence
    "Backdoor / Remote Access": ["reverse shell", "webshell", "rce"],
    "Persistence Mechanisms": ["startup folder", "cron job", "registry autorun"],

    # Supply Chain & Third-Party Risks
    "Third-Party Compromise": ["npm package", "python dependency", "malicious library"],

    # API & Application Abuse
    "Excessive API Calls": ["rate limit exceeded", "api abuse", "flood request"],
    "Token Leakage": ["bearer token", "oauth token exposed"],

    # Cloud & Container
    "Misconfigured Cloud IAM": ["s3 policy public", "iam overly permissive", "bucket policy open"],
    "Container Escape Risk": ["docker socket", "privileged container", "kubernetes misconfig"],

    # Network & Lateral Movement
    "VPN / Remote Access Weakness": ["default vpn creds", "openvpn misconfig", "pptp exposed"],
    "SMB / File Share Exposure": ["smb share open", "anonymous smb access"],

    # Data & Privacy
    "PII Exposure": ["ssn", "credit card", "passport number"],
    "Database Leakage": ["mysql dump", "mongodb exposed", "postgres backup"],

    # Security Configuration
    "Weak Encryption / TLS Misconfig": ["sslv3", "rc4 cipher", "weak dh key"],
    "Unprotected Secrets in Repos": [".env", ".pem", "private.key"]
}

# ==================================================
# 🧠 MITRE ATT&CK MAPPING (Expanded for any perspective) (Mapping can be added if need)
# ==================================================
MITRE_MAP = {
    "Exposed Administrative Interface": ["TA0001 Initial Access", "TA0004 Privilege Escalation"],
    "Authentication Weakness": ["TA0006 Credential Access"],
    "Credential Exposure": ["TA0006 Credential Access", "TA0009 Collection"],
    "Open Network Services": ["TA0008 Lateral Movement"],
    "Unrestricted Internal Service": ["TA0008 Lateral Movement"],
    "Cloud Storage Exposure": ["TA0009 Collection"],
    "Outdated Software": ["TA0001 Initial Access"],
    "Legacy Protocol Usage": ["TA0006 Credential Access"],
    "Debug Artifact Exposure": ["TA0043 Reconnaissance"],
    "Insecure Security Headers": ["TA0002 Execution"],
    "CORS Misconfiguration": ["TA0009 Collection"],
    "Metadata Disclosure": ["TA0043 Reconnaissance"],
    "Sensitive File Exposure": ["TA0009 Collection"],
    "Excessive Privilege Assignment": ["TA0004 Privilege Escalation"],
    "Improper Access Control": ["TA0005 Defense Evasion"],
    "Exposed API Endpoint": ["TA0043 Reconnaissance"],
    "GraphQL Introspection Enabled": ["TA0043 Reconnaissance"],
    "Phishing Susceptibility": ["TA0001 Initial Access", "TA0006 Credential Access"],
    "Malicious Email Indicators": ["TA0001 Initial Access", "TA0003 Persistence"],
    "Backdoor / Remote Access": ["TA0011 Command and Control", "TA0005 Defense Evasion"],
    "Persistence Mechanisms": ["TA0003 Persistence"],
    "Third-Party Compromise": ["TA0042 Resource Development", "TA0001 Initial Access"],
    "Excessive API Calls": ["TA0007 Discovery", "TA0008 Lateral Movement"],
    "Token Leakage": ["TA0006 Credential Access"],
    "Misconfigured Cloud IAM": ["TA0008 Lateral Movement", "TA0009 Collection"],
    "Container Escape Risk": ["TA0005 Defense Evasion", "TA0008 Lateral Movement"],
    "VPN / Remote Access Weakness": ["TA0006 Credential Access", "TA0008 Lateral Movement"],
    "SMB / File Share Exposure": ["TA0008 Lateral Movement", "TA0009 Collection"],
    "PII Exposure": ["TA0009 Collection", "TA0010 Exfiltration"],
    "Database Leakage": ["TA0009 Collection", "TA0010 Exfiltration"],
    "Weak Encryption / TLS Misconfig": ["TA0002 Execution", "TA0005 Defense Evasion"],
    "Unprotected Secrets in Repos": ["TA0006 Credential Access", "TA0009 Collection"]
}
# 📊 RISK SCORING
# ==================================================
def calculate_risk(findings):
    """Dynamic risk score based on number of findings (max 10)."""
    return min(len(findings) * 2, 10)

def risk_level(score):
    """Convert numeric score to severity label."""
    return "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


# ==================================================

# ==================================================
# 📚 CORPUS MERGE LOGIC
# ==================================================
# ==================================================
# 📚 CTI CORPUS LOADER
# ==================================================
CORPUS_DIR = "corpus_cti"

def load_corpus(signal):
    fname = signal.lower().replace(" ", "_") + ".txt"
    path = os.path.join(CORPUS_DIR, fname)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return None

# ==================================================
# 🔍 THREAT DETECTION
# ==================================================
# ==================================================
# 🔍 THREAT DETECTION WITH SOURCE LINES
# ==================================================
def detect_signals(text):
    """
    Returns:
    {
        signal_name: {
            "patterns": [matched_patterns],
            "lines": [source_lines]
        }
    }
    """
    findings = {}
    lines = text.splitlines()
    for signal, patterns in THREAT_SIGNALS.items():
        for p in patterns:
            matched_lines = [line for line in lines if p.lower() in line.lower()]
            if matched_lines:
                findings.setdefault(signal, {"patterns": [], "lines": []})
                findings[signal]["patterns"].append(p)
                findings[signal]["lines"].extend(matched_lines)
    return findings
# ==================================================
# 🤖 LLaMA CTI ANALYSIS (DEFENSIVE) – VWPA STYLE
# ==================================================
def llama_cti_analysis(signal, indicators, source_lines, temperature,
                       use_internal=False,
                       uploaded_folder_zip=None,
                       uploaded_multi_zip=None):

    corpus_text_extra = ""

    # Internal corpus
    if use_internal:
        corpus = load_corpus(signal)
        if corpus:
            corpus_text_extra += f"\n[INTERNAL CORPUS]\n{corpus}\n"

    # Uploaded folder ZIP corpus
    if uploaded_folder_zip:
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(uploaded_folder_zip) as z:
                z.extractall(tmpdir)
            path = os.path.join(tmpdir, signal.lower().replace(" ", "_") + ".txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    corpus_text_extra += f"\n[UPLOADED FOLDER CORPUS]\n{f.read()}\n"

    # Uploaded multi ZIP corpus
    if uploaded_multi_zip:
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(uploaded_multi_zip) as z:
                z.extractall(tmpdir)
            path = os.path.join(tmpdir, signal.lower().replace(" ", "_") + ".txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    corpus_text_extra += f"\n[UPLOADED MULTI CORPUS]\n{f.read()}\n"

    use_corpus_flag = bool(corpus_text_extra.strip())

    # ===== PROMPT WITH SOURCE LINES =====
    source_lines_text = "\n".join(source_lines)
    prompt = f"""
You are a senior blue-team cyber threat intelligence analyst.

Analyze the following threat signal from a defensive perspective.
Think deeply and autonomously about attacker objectives and defensive strategies.

Signal:
{signal}

Observed Indicators:
{indicators}

Source Lines from Recon / Scan:
{source_lines_text}
"""

    if use_corpus_flag:
        prompt += f"""
[DEFENSIVE REFERENCE CORPUS – USE IF HELPFUL]
Use this information to expand or enrich your reasoning, but rely primarily on your own expert analysis.

{corpus_text_extra}
"""

    prompt += """
Instructions:

- Think critically and independently first.
- If corpus is available, use it to enrich (not replace) your reasoning.

Provide a structured DEFENSIVE analysis with these sections:

1. Threat Significance
2. Attacker Objectives
3. Attack Chain Potential
4. MITRE Tactical Relevance
5. Early Warning Indicators
6. Defensive Priorities
7. Strategic Security Improvements

Rules:
- Defensive only
- No exploit steps or payloads
- Corpus is optional and supplemental
"""

    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a defensive cyber threat intelligence expert."},
            {"role": "user", "content": prompt}
        ],
        temperature=temperature,
        max_tokens=1000
    )

    return response.choices[0].message.content.strip()


# ==================================================
# ==================================================
# 📊 DASHBOARD
# ==================================================
def plot_dashboard(findings):
    if not findings:
        return
    # Use dynamic risk calculation instead of undefined RISK_BASE
    scores = [calculate_risk(findings[s]) for s in findings]
    plt.figure()
    plt.bar(findings.keys(), scores, color='tomato')
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Risk Score")
    plt.title("Advanced CTI Risk Dashboard")
    plt.tight_layout()
    st.pyplot(plt)


# ==================================================
# 📄 REPORT
# ==================================================
def build_report(results, findings):
    lines = ["Advanced NLP-Driven Cyber Threat Intelligence Report", "="*90]
    total = 0
    for signal in findings:
        score = calculate_risk(findings[signal])
        severity = risk_level(score)
        total += score
        lines.extend([
            "\n" + "="*90,
            f"SIGNAL: {signal}",
            f"Severity: {severity}",
            f"Risk Score: {score}",
            f"MITRE Mapping: {', '.join(MITRE_MAP.get(signal, []))}",
            "-"*90,
            results[signal]
        ])
    avg = round(total/max(len(findings),1),2)
    lines.extend([
        "\n" + "="*90,
        f"Overall Average Risk Score: {avg}",
        "Intelligence Confidence: Moderate to High",
        "="*90
    ])
    return "\n".join(lines)

# ==================================================
# 🖥️ STREAMLIT UI
# ==================================================
st.set_page_config(page_title="AI CTI Analyzer", layout="wide")
st.title("🧠 AI Cyber Threat Intelligence Analyzer")

st.sidebar.header("Configuration")
temperature = st.sidebar.slider("LLaMA Temperature", 0.0, 1.0, 0.25, 0.05)

use_internal = st.sidebar.checkbox("Use Internal Corpus")
uploaded_folder_zip = st.sidebar.file_uploader("Upload Corpus Folder ZIP", type=["zip"])
uploaded_multi_zip = st.sidebar.file_uploader("Upload Multi-Corpus ZIP", type=["zip"])

uploaded_txt = st.file_uploader("Upload Recon / Scan TXT", type=["txt"])

if uploaded_txt:
    text = uploaded_txt.read().decode("utf-8", errors="ignore")

    if st.button("Run Advanced CTI Analysis"):
        findings = detect_signals(text)
        if not findings:
            st.warning("No significant threat signals detected.")
            st.stop()

        results = {}
        with st.spinner("Running NLP threat intelligence reasoning..."):
            for signal in findings:
                indicators = findings[signal]["patterns"]
                source_lines = findings[signal]["lines"]

                # Display expandable section for source lines
                with st.expander(f"Source Lines for {signal} ({len(source_lines)} lines)"):
                    st.text("\n".join(source_lines))

                # LLaMA reasoning
                results[signal] = llama_cti_analysis(
                    signal,
                    indicators,
                    source_lines,
                    temperature,
                    use_internal=use_internal,
                    uploaded_folder_zip=uploaded_folder_zip,
                    uploaded_multi_zip=uploaded_multi_zip
                )

        st.success("Advanced CTI Analysis Complete")
        st.subheader("📊 Risk Dashboard")
        plot_dashboard({s: f["patterns"] for s, f in findings.items()})

        report = build_report(results, {s: f["patterns"] for s, f in findings.items()})
        st.subheader("📄 Intelligence Report")
        st.text_area("Report Output", report, height=600, disabled=True)
        st.download_button(
            "Download Report (.txt)",
            report,
            file_name=f"advanced_cti_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )