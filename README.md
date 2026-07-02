# Vulnerability Assessment Report: testphp.vulnweb.com

This repository contains the deliverables for **Cyber Security Task 1 (2026)** of the Future Interns internship training program. The objective is to perform a passive, read-only security assessment of a live website, identify vulnerabilities, classify risks, and suggest actionable business-friendly remediation steps.

---

## 🔍 Executive Summary
A passive security audit was conducted on the target website `http://testphp.vulnweb.com` (a public test domain designed specifically for vulnerability scanning practice). The audit was performed strictly within a **read-only, passive scope** to ensure compliance with ethical guidelines. 

The assessment revealed a critical security posture (Overall Rating: **F / 32%**):
* **02 High-Risk Vulnerabilities**
* **03 Medium-Risk Vulnerabilities**
* **03 Low/Info-Risk Vulnerabilities**

Immediate remediation is strongly recommended, especially regarding the upgrade of the EOL (End-of-Life) PHP runtime and the deployment of basic HTTP security headers.

---

## 🛠️ Assessment Methodology & Tools
The audit was completed without active intrusion, exploitation, or brute-forcing. The following tools and methods were utilized:
1. **Passive Security Scanner (`passive_scanner.py`):** A custom-built Python script utilizing standard networking and HTTP client libraries (`urllib`, `socket`, `http.cookiejar`) to securely audit target services, analyze response headers, and examine cookies.
2. **Browser Developer Tools:** Used to manually inspect cookie flags, raw HTTP response headers, and network parameters.
3. **Nmap (Service Port Profiling):** Basic port check emulation to discover exposed services.

---

## 📂 Repository Structure
```directory
.
├── evidence/
│   ├── scan_results.txt      # Plaintext log from the custom scanner
│   └── scan_results.json     # Structured JSON scan output
├── passive_scanner.py        # Custom python security scanner script
├── vulnerability_report.html # Premium interactive HTML vulnerability report
└── README.md                 # Project documentation & summary (this file)
```

---

## 📊 Summary of Findings

| Vulnerability / Exposure | Severity | CWE ID | Business Impact |
| :--- | :---: | :---: | :--- |
| **Missing Content Security Policy (CSP)** | **High** | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | Allows attackers to perform Cross-Site Scripting (XSS), steal sessions, or inject malicious code. |
| **Outdated PHP Version Disclosure (PHP 5.6.40)** | **High** | [CWE-937](https://cwe.mitre.org/data/definitions/937.html) | The system runs a PHP version that has been End-of-Life since 2018, exposing it to known exploits. |
| **Missing X-Frame-Options Header** | **Medium** | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | Leaves the site vulnerable to Clickjacking attacks (framing within malicious pages). |
| **Insecure Session Cookie Configuration** | **Medium** | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Session cookies lack `Secure`, `HttpOnly`, and `SameSite` flags, allowing session sniffing or theft. |
| **Web Server Signature Disclosure** | **Medium** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Leaks `nginx/1.19.0 (Ubuntu)` version details, aiding attackers in locating target-specific exploits. |
| **Missing X-Content-Type-Options Header** | **Low** | [CWE-116](https://cwe.mitre.org/data/definitions/116.html) | Permits browsers to sniff MIME-types, potentially executing uploaded non-script files as scripts. |
| **Missing Referrer-Policy Header** | **Low** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Browser default behavior may leak sensitive URL parameters to third-party links. |
| **Missing Strict-Transport-Security (HSTS)** | **Low** | [CWE-523](https://cwe.mitre.org/data/definitions/523.html) | Fails to force TLS/HTTPS connections, exposing traffic to Man-in-the-Middle (MitM) attacks. |

---

## 🛡️ Remediation Roadmap

The identified vulnerabilities should be resolved in the following priority:

### Phase 1: Immediate Action (24-48 Hours)
1. **Upgrade Backend Platform:** Migrate the web backend from PHP 5.6.40 to a modern supported version (PHP 8.2+).
2. **Disable PHP Signatures:** Modify `php.ini` to set `expose_php = Off` to stop disclosing the backend language version.

### Phase 2: Security Configurations (Next 7 Days)
1. **Implement Frame Protection:** Add the header `X-Frame-Options: SAMEORIGIN` to your web server configurations (Nginx/Apache).
2. **Apply Script Restrictions:** Build and enforce a robust `Content-Security-Policy` header.
3. **Secure Session Cookie Management:** Enable flags on cookies inside application settings:
   ```ini
   session.cookie_httponly = True
   session.cookie_secure = True
   session.cookie_samesite = "Lax"
   ```

### Phase 3: Infrastructure Hardening (Next 30 Days)
1. **Disable Web Server Banners:** Configure Nginx with `server_tokens off;` to hide server version details.
2. **Deploy Transit & MIME Protection Headers:** Configure `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Strict-Transport-Security`.

---

## 📄 Final Deliverable Link
To view the formatted interactive audit report with complete technical findings, evidence snippets, and code blocks, open:
👉 **[vulnerability_report.html](./vulnerability_report.html)** (Open in any web browser to view or print as a PDF)
"# FUTURE_CS_01" 
"# FUTURE_CS_01" 
