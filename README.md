# 🛡️ Sentinel-X PhishGuard (v1.0)

> **Advanced Phishing URL Detection & SSL Forensics Tool** > *Detects malicious links, analyzes SSL certificates, and traces redirect chains in real-time.*

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-Phishing_Detection-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

## 📜 Overview
**Sentinel-X PhishGuard** is a Python-based cybersecurity tool designed to analyze suspicious URLs. It performs deep inspection of the target's infrastructure including SSL certificate age, redirect chains (to unmask shorteners like bit.ly), and open ports to calculate a **Phishing Risk Score**.

## ✨ Key Features
* **🔗 Redirect Tracing:** Unmasks hidden destination URLs behind shorteners.
* **🔒 SSL Forensics:** Analyzes Certificate Issuer, Age, and Validity. Detects "Free SSL" (Let's Encrypt) used by fresh phishing sites.
* **qo Port Scanning:** Checks for suspicious open ports (FTP, SSH, MySQL, Alt-HTTP).
* **🧠 Intelligent Scoring:** Calculates a risk score (0-100) based on multiple heuristics.
* **🎨 Colorized Output:** Easy-to-read terminal report.

## 🛠️ Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/rehan-qx/PhishGuard.git](https://github.com/rehan-qx/PhishGuard.git)
    cd PhishGuard
    ```

2.  **Install Dependencies:**
    You need a few Python libraries to run the tool.
    ```bash
    pip install requests colorama python-whois
    ```

## 🚀 Usage

Run the script using Python 3:

```bash
python3 PhishGuard.py
```
---
## 📊 How It Works (The Logic)
The tool calculates a Risk Score based on these factors:
```text
+--------------------------------------------------------------------+
| Factor      | Condition                              | Risk Added  |
+--------------------------------------------------------------------+
| Redirects  | More than 2 redirects found             | +30 Points  |
| SSL Age    | Certificate is < 14 Days old            | +50 Points  |
| SSL Issuer | Free SSL (Let's Encrypt) on new site    | +20 Points  | 
| No SSL     | Site is HTTP only                       | +80 Points  |
| Keywords   | "URL contains ""@"" or ""-"" (hyphens)" | +20 Points  |
+--------------------------------------------------------------------+

* Score > 70: 🔴 DANGEROUS (Likely Phishing)

* Score > 40: 🟡 SUSPICIOUS (Caution Advised)

* Score < 40: 🟢 SAFE (Legitimate)
```
---
## ⚠️ Disclaimer
### This tool is for Educational Purposes and Ethical Testing ONLY.

Do not use this tool to scan government or military networks without permission.

The developer is not responsible for any misuse of this software.

### Developed by **[.0xR00t]** | Sentinel-X PhishGuard (v1.0)
