# 👁️ Phr33k eYe

**All-in-one reconnaissance & vulnerability suite — one target, one click, everything you need to know.**

Phr33k eYe v2.0.0 is a lightweight Python GUI toolkit built for authorized security testing. Type a domain or an IP, pick a module, press **RUN SCAN** — and get a complete picture of your target in seconds. No terminal gymnastics, no juggling ten different tools.

> ⚠️ **Authorized testing only.** Scanning systems without the owner's permission is illegal. Phr33k eYe is built for professionals testing their own systems or systems they are hired to test.

---

## 🔍 Modules

| Module | What it does |
|---|---|
| **DNS & IP Recon** | Full DNS and IP intelligence on any target |
| **Subdomain Finder** | Enumerates subdomains to map the real attack surface |
| **Admin Panel Finder** | Locates exposed admin/login panels |
| **Tech / CMS Detect** | Fingerprints the stack: CMS, frameworks, server tech |
| **WAF & Payment Detect** | Detects web application firewalls and payment setups |
| **Port Scanner** | Nmap-powered port scanning with service detection |
| **Vulnerability & Exploit Checker** | Lightweight Nuclei-style engine: probes for exposed `.env`/`.git`, debug pages, missing security headers, known CVE signatures and common misconfigurations |
| **SQLi Scanner** | SQL injection detection for authorized assessments |
| **SQLi DB Dumper / Explorer** | Database enumeration modules for in-scope engagements |
| **WP Plugins/Themes** | WordPress plugin & theme enumeration |
| **WP Exploit Check** | Checks WordPress setups against known exploit signatures |

Plus: live console with timestamped logging, **Export console log**, and **Stop active scan** control.

## ⚡ Why Phr33k eYe?

- **One click** — enter the target once, every module is one press away
- **One file** — a single small Python script with a clean dark GUI
- **Fast picture** — recon, detection and vulnerability checks in one place
- **Built by a practitioner** — made by Phr33k, an authorized vulnerability assessment researcher, for real engagements

## 🚀 Quick start

```bash
# Requirements: Python 3 + Nmap (for the Port Scanner module)
python phr33k_eye.py
```

1. Launch the app
2. Select a module on the left
3. Enter a target (`example.com` or `192.168.1.1`)
4. Press **RUN SCAN**

## 📜 License & legal

For authorized security testing, research and education only. You are responsible for having written permission to test any target you scan. The author assumes no liability for misuse.

---

**by Geeks Hub · Powered by Phr33k**
🔗 https://geekshub.xo.je · https://github.com/g33ks-hub
