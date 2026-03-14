---
layout: attack-chain
title: Infostealer Attack Chain
subtitle: "How infostealer operators all follow the same five-stage chokepoint sequence — regardless of family, brand, or C2 infrastructure."
last_updated: 2025-01-15
permalink: /attack-chains/infostealers/
show_ttp_overlap: true
ttp_data_key: infostealer_ttp_overlap

stages:
  - id: distribution
    label: Distribution
    mitre_tactic: "TA0001"
    mitre_techniques:
      - id: "T1608.005"
        name: "Link Target (SEO)"
      - id: "T1566.002"
        name: "Spearphishing Link"
    detection_status: detected
    attacker_action: "Malvertising / SEO poison"
    systems: "Browser · DNS"
    detection_signals:
      - "Download from newly registered domain (<90 days old)"
      - "Browser navigating to typosquatted software download site"
      - "Installer with missing or untrusted digital signature"
  - id: execution
    label: Execution
    mitre_tactic: "TA0002"
    mitre_techniques:
      - id: "T1204.002"
        name: "Malicious File"
      - id: "T1059.005"
        name: "Visual Basic"
      - id: "T1218.005"
        name: "Mshta"
    detection_status: detected
    attacker_action: "LOLBin chain / fake installer"
    systems: "Endpoint"
    detection_signals:
      - "Executable launched from %USERPROFILE%\\Downloads\\ or %TEMP%\\"
      - "Browser process spawning unexpected child process"
      - "LOLBin chain: mshta → wscript → rundll32 (no legitimate parent)"
    chokepoint_links:
      - label: "ClickFix Techniques"
        slug: "clickfix-techniques"
  - id: collection
    label: Collection
    mitre_tactic: "TA0009"
    mitre_techniques:
      - id: "T1555.003"
        name: "Credentials from Browsers"
      - id: "T1539"
        name: "Steal Web Session Cookie"
    detection_status: exploited
    attacker_action: "Browser DB / DPAPI decrypt"
    systems: "Endpoint · Browser"
    detection_signals:
      - "Non-browser process reading Chrome/Firefox SQLite credential stores"
      - "DPAPI CryptUnprotectData call from unexpected process"
      - "Bulk file reads under %APPDATA%\\*\\Chromium\\ or %APPDATA%\\Mozilla\\"
    chokepoint_links:
      - label: "Browser Credential Theft"
        slug: "browser-credential-theft"
  - id: exfiltration
    label: Exfiltration
    mitre_tactic: "TA0010"
    mitre_techniques:
      - id: "T1041"
        name: "Exfiltration Over C2"
      - id: "T1048"
        name: "Exfil Over Alt Protocol"
    detection_status: detected
    attacker_action: "HTTPS POST to C2 / Telegram"
    systems: "Network · Firewall"
    detection_signals:
      - "Non-browser process making HTTPS POST with payload >1 MB"
      - "Outbound connection to Telegram Bot API (api.telegram.org) from non-user process"
      - "Compressed archive (.zip/.7z) created then immediately sent over network"
  - id: monetization
    label: Monetization
    mitre_tactic: "TA0040"
    mitre_techniques:
      - id: "T1657"
        name: "Financial Theft"
      - id: "T1078"
        name: "Valid Accounts (downstream)"
    detection_status: unknown
    attacker_action: "IAB sale · Session replay"
    systems: "Dark web · SaaS"
    detection_signals:
      - "VPN/SaaS login from new geo-location with valid credentials (downstream)"
      - "Session token reuse from unfamiliar IP/device fingerprint"
      - "Account behavior anomaly after credential exposure window"

actors:
  - name: RedLine
    status: Disrupted
    distribution: "Malvertising / cracked software SEO"
    execution: "User double-clicks fake installer EXE"
    collection: "Chrome/Firefox SQLite + crypto wallets (DPAPI)"
    exfiltration: "HTTPS POST to C2 panel"
    monetization: "IAB dark web marketplace sale"
  - name: LummaC2
    status: Active
    distribution: "Fake CAPTCHA / ClickFix lure pages"
    execution: "LOLBin chain (mshta → wscript → rundll32)"
    collection: "Browsers + 2FA extensions + crypto wallets (DPAPI)"
    exfiltration: "Encrypted HTTPS POST to rotating C2"
    monetization: "IAB sale + direct RaaS operator supply"
  - name: Vidar
    status: Active
    distribution: "Malvertising / YouTube description links"
    execution: "MSI / NSIS installer execution"
    collection: "Browsers + 2FA tokens + crypto wallets (DPAPI + Telegram token)"
    exfiltration: "HTTP POST + Telegram Bot API C2"
    monetization: "IAB marketplace listing"
  - name: StealC
    status: Active
    distribution: "SEO poisoning / malvertising"
    execution: "User-executed signed-looking binary"
    collection: "Browsers + Discord tokens + Telegram sessions"
    exfiltration: "HTTP POST to admin panel"
    monetization: "IAB sale / direct buyer negotiation"
  - name: Raccoon
    status: Disrupted
    distribution: "Phishing / malvertising"
    execution: "User-executed EXE or MSI"
    collection: "Browsers + email clients + crypto wallets"
    exfiltration: "HTTP POST to C2"
    monetization: "IAB marketplace"

chokepoints:
  distribution: "Delivery mechanism reaches target user's endpoint"
  execution: "User action triggers payload (no AV block / sandbox)"
  collection: "File system access to browser profile dirs + DPAPI decryption privilege"
  exfiltration: "Outbound network connectivity from infected host"
  monetization: "Harvested credential data has market value; buyer infrastructure exists"
---

# Infostealer Attack Chain

## Overview

Infostealers have become the foundation of the RaaS ecosystem. Initial Access Brokers
(IABs) use infostealers to harvest credentials and session tokens, which are then sold
to ransomware operators with pre-mapped environments.

**Market Value:** $10–$100K per enterprise access package (HudsonRock, RedCanary)

---

## Example: RedLine → BlackBasta Pipeline

### Timeline
```
Day 1:
T+0:00  - User searches "adobe crack download"
T+0:05  - Clicks malicious SEO result
T+0:10  - Downloads fake installer (RedLine payload)
T+0:12  - User executes installer
T+0:13  - RedLine harvests credentials, session tokens
T+0:15  - Exfiltrates to C2 (15MB archive)
T+0:16  - RedLine self-deletes

Day 7:
        - Credentials appear on dark web marketplace
        - IAB lists: "Enterprise VPN access, 5000+ employees, $50K"

Day 14:
        - BlackBasta operators purchase access
        - Login using stolen session token (bypasses MFA)
        - Begins reconnaissance

Day 15:
        - Ransomware deployment
```

### Chokepoints Hit
1. **Distribution**: SEO poisoning → browser download
2. **Execution**: User double-click on fake installer
3. **Collection**: Browser SQLite database access + DPAPI decryption
4. **Exfiltration**: HTTPS POST to C2 domain
5. **Monetization**: IAB marketplace listing

### Detection Opportunities
- **T+0:05**: Download from newly registered domain
- **T+0:10**: Unsigned executable in Downloads folder
- **T+0:12**: Process execution from user Downloads
- **T+0:13**: Access to `%APPDATA%\*\Chromium\*\Login Data`
- **T+0:15**: Non-browser process making HTTPS POST with large payload
- **Day 14**: VPN login from new geo-location with valid creds

---

## Chokepoint Detection Details

### Collection Phase (Highest Value)
**Why it matters:** Preventing collection prevents exfiltration.

**Log Sources:**
- Sysmon Event ID 10 (Process Access)
- Sysmon Event ID 11 (File Creation)
- File system monitoring

**Detection:**
```
Process: [Not browser.exe]
File Access:
  - %APPDATA%\Google\Chrome\User Data\Default\Login Data
  - %APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json
  - %LOCALAPPDATA%\Microsoft\Windows\Credentials\*
Action: Read access
```

### Exfiltration Phase (Last Chance)
**Why it matters:** Prevents credential compromise reaching IAB marketplace.

**Log Sources:**
- Network connection logs (Sysmon Event ID 3)
- DNS query logs
- Proxy/firewall logs

**Detection:**
```
Process: [Not browser.exe]
Network: Outbound HTTPS POST
Destination:
  - Newly registered domain (<90 days)
  - Known C2 infrastructure
  - Telegram/Discord API
Payload Size: >1MB
User Agent: Suspicious or missing
```

### Execution Phase (Early Prevention)
**Why it matters:** Stops before collection begins.

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- File creation events

**Detection:**
```
Parent: explorer.exe OR browser process
Process: *.exe from:
  - %USERPROFILE%\Downloads\
  - %TEMP%\
  - %APPDATA%\Local\Temp\
Digital Signature: Missing OR untrusted
```

---

## RaaS Ecosystem Impact

### How Infostealers Enable Ransomware

**Traditional Model (Pre-2020):**
```
Attacker → Phishing → Credential Theft → Lateral Movement → Ransomware
Timeline: Weeks to months
```

**Modern IAB Model (2020+):**
```
Infostealer Operator → Mass Infection → Credential Harvest → IAB Sale
                                                                ↓
Ransomware Operator ← Purchase Access ← Pre-Mapped Environment
Timeline: Days to hours
```

**Result:**
- Time-to-Ransom (TTR) decreased from weeks to <24 hours
- Ransomware operators skip initial access phase entirely
- Defenders face pre-authenticated attackers with valid credentials
- MFA bypassed via session token theft

### IAB Marketplace Listings (Typical)

```
[VIP] Fortune 500 Manufacturing - $75K
- Domain admin credentials
- VPN access (GlobalProtect)
- 8,000 employees
- Revenue: $2.5B
- Network map included
- Veeam backup server access

[Premium] Healthcare Provider - $50K
- Local admin on 200+ endpoints
- EMR system access
- 1,500 employees
- HIPAA data confirmed
```

---

## Key Metrics

**Infostealer Prevalence (HudsonRock, RedCanary):**
- 2023: 10M+ infections annually
- 2024: 15M+ infections annually (50% increase)

**Credential Exposure:**
- Average: 50+ credentials per victim
- Enterprise: 200+ credentials per victim
- Session tokens: 90%+ bypass MFA

**IAB Market Size:**
- Active brokers: 500+
- Average listing price: $5K–$100K
- Time from infection to sale: 7–14 days

---

## References

- [HudsonRock Infostealer Data](https://www.hudsonrock.com/)
- [RedCanary Threat Detection Report](https://redcanary.com/)
- MITRE ATT&CK: T1555 (Credentials from Password Stores)
- MITRE ATT&CK: T1539 (Steal Web Session Cookie)
- [Cyberint IAB Analysis](https://cyberint.com/)

## Related Attack Chains

- [Ransomware](./ransomware.md) - Often follows infostealer-provided access
