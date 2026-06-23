# 🎣 Phishing Email Investigation — Brazilian Tax Scam (IRPF)

> **Analyst:** Gaurav | Cybersecurity Enthusiast  
> **Tool:** VirusTotal, MXToolbox, AbuseIPDB, Python3  
> **Technique Detected:** T1566.001 — Spearphishing Attachment (MITRE ATT&CK)  
> **Verdict:** ✅ True Positive — HIGH Severity | Trojan:PDF/Phishing.A

---

## 📌 Project Overview

This project is a real-world phishing email investigation performed on a sample from the **Phishing Pot** public dataset (`sample-1000.eml`). The investigation follows a standard SOC L1 triage workflow:

Email received → Header analysis → Attachment extraction → IOC lookup → Verdict → Remediation

---

## 🎯 What Was Found

A phishing email impersonating the **Brazilian Federal Revenue Service (IRPF)** was analyzed:

| Detail | Value |
|---|---|
| Sender | `prestonconstance587@gmail.com` (throwaway Gmail) |
| Subject | "Liberacao de IRPF" (Brazilian tax refund lure) |
| Attachment | `csWuYjyqO2IR.pdf` (random obfuscated name) |
| Origin IP | `20.97.213.223` (Microsoft Azure VM — attacker controlled) |
| VirusTotal | **23/63 vendors flagged MALICIOUS** |
| Threat Label | `trojan.abphisher/atmn` — Trojan:PDF/Phishing.A |
| Classification | ✅ True Positive — HIGH Severity |

---

## 🔍 Investigation Methodology

### Step 1: Email Header Analysis (MXToolbox)
- Extracted headers from `.eml` file using terminal
- Analyzed via MXToolbox Email Header Analyzer
- Checked SPF / DKIM / DMARC authentication results

**Key Finding — Legitimate Service Abuse:**
```
SPF:   PASS ⚠️  (Gmail is authorized — attacker used real Gmail)
DKIM:  PASS ⚠️  (Gmail signed the email)
DMARC: PASS ⚠️  (Policy satisfied — but attacker's tactic)
```
All checks PASS — but this is NOT safe. Attacker deliberately used Gmail to bypass email filters. This tactic is called **Legitimate Service Abuse (T1550)**.

### Step 2: Attachment Extraction (Python3)
```python
import email

with open('sample-1000.eml', 'rb') as f:
    msg = email.message_from_bytes(f.read())

for part in msg.walk():
    if part.get_filename() == 'csWuYjyqO2IR.pdf':
        payload = part.get_payload(decode=True)
        with open('suspicious.pdf', 'wb') as out:
            out.write(payload)
        print(f"PDF extracted! Size: {len(payload)} bytes")
```
**Result:** PDF extracted — 97,566 bytes (95.28 KB)

### Step 3: Hash Generation
```bash
md5sum suspicious.pdf
# f1b1ac7839d2b2a1e458b5d87c7b2ca2

sha256sum suspicious.pdf
# cfc5fbc759dcc599c8329dd94f9364394c7b1e875d6ff515c7337e00fb1f30cf
```

### Step 4: VirusTotal Hash Lookup
- SHA256 hash submitted to VirusTotal
- **Result: 23/63 vendors flagged as MALICIOUS**
- Threat categories: `trojan`, `phishing`
- Family labels: `abphisher`, `atmn`, `ocnw`

### Step 5: IP Reputation Check (AbuseIPDB)
- Sending IP `209.85.160.178` checked on AbuseIPDB
- **Result: Google LLC — 84 reports, 0% abuse confidence**
- Confirms Gmail SMTP abuse — not a malicious IP itself, but used by attacker

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Defense Evasion | Masquerading (random PDF filename) | T1036 |
| Defense Evasion | Abuse Elevation Control Mechanism | T1550 |
| Credential Access | Phishing for Information | T1598 |

---

## 🔎 IOC Summary

| IOC Type | Value | Verdict |
|---|---|---|
| Sender Email | `prestonconstance587@gmail.com` | 🚨 Throwaway attacker account |
| Sending IP | `209.85.160.178` | ⚠️ Google Gmail SMTP (legitimate service abused) |
| Origin IP | `20.97.213.223` | 🚨 Azure VM — attacker infrastructure |
| PDF SHA256 | `cfc5fbc759...f30cf` | 🚨 23/63 MALICIOUS |
| PDF MD5 | `f1b1ac7839...2ca2` | 🚨 Confirmed Trojan |
| Subject | Liberacao de IRPF | 🚨 Tax refund social engineering |
| Attachment | csWuYjyqO2IR.pdf | 🚨 Random name — obfuscation |

---

## ✅ Recommended Remediation

| Priority | Action |
|---|---|
| 🔴 IMMEDIATE | Block sender: prestonconstance587@gmail.com |
| 🔴 IMMEDIATE | Quarantine/purge email from all mailboxes |
| 🔴 IMMEDIATE | Block PDF hash on EDR/AV systems |
| 🟠 HIGH | Block origin IP 20.97.213.223 at firewall |
| 🟠 HIGH | Alert users about IRPF tax phishing campaign |
| 🟠 HIGH | Add IOCs to SIEM detection rules |
| 🔵 MEDIUM | Check EDR logs — did anyone open the PDF? |
| 🔵 MEDIUM | Submit IOCs to threat intel sharing (MISP) |

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| Python3 | PDF extraction from .eml file |
| VirusTotal | PDF hash reputation (23/63 malicious) |
| MXToolbox | Email header analysis, SPF/DKIM/DMARC |
| AbuseIPDB | Sender IP reputation check |
| Kali Linux | Lab environment |
| Phishing Pot Dataset | Real-world phishing email samples |

---

## 📁 Repository Structure

```
phishing-investigation/
├── README.md                          # This file
├── Phishing_Investigation_Report.pdf  # Full investigation report with screenshots
├── sample-1000.eml                    # Original phishing email sample
├── screenshots/
│   ├── virustotal_23_63.png          # VirusTotal 23/63 malicious result
│   ├── mxtoolbox_headers.png         # MXToolbox header analysis
│   ├── mxtoolbox_spf_dkim.png        # SPF/DKIM/DMARC results
│   ├── abuseipdb_result.png          # AbuseIPDB IP reputation
│   └── terminal_extraction.png       # PDF extraction + hash commands
```

---

## 🎓 Skills Demonstrated

- Phishing email analysis — header inspection, SPF/DKIM/DMARC
- PDF attachment extraction using Python3
- File hash generation (MD5, SHA256) and VirusTotal lookup
- IP reputation analysis (AbuseIPDB)
- Legitimate Service Abuse detection (Gmail SMTP abuse)
- MITRE ATT&CK framework mapping
- SOC triage workflow and incident report writing

---

*This project demonstrates hands-on SOC investigation skills using 
real-world phishing samples from the Phishing Pot public dataset, 
analyzed in a Kali Linux environment..*
