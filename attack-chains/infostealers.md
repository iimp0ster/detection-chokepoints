# Infostealer Attack Chain

**Last Updated:** 2025-01-15

## Overview

Infostealers have become the foundation of the RaaS ecosystem. Initial Access Brokers
(IABs) use infostealers to harvest credentials and session tokens, which are then sold
to ransomware operators with pre-mapped environments.

**Market Value:** $10-$100K per enterprise access package (HudsonRock, RedCanary)

## Attack Chain Chokepoints

```
Distribution → Execution → Collection → Exfiltration → Monetization
     ↓            ↓            ↓            ↓              ↓
 [Delivery]  [User Action] [File/Memory] [Network C2]   [IAB Sale]
```

## Chokepoint Breakdown

### 1. Distribution
**Chokepoints Used:**
- Malvertising (fake software updates)
- SEO poisoning (cracked software)
- Phishing campaigns
- Software supply chain compromise
- Malicious browser extensions

**Key Prerequisites:**
- Hosting infrastructure
- User action required
- Download mechanism (browser, installer)

**Detection Opportunity:**
- Browser download from suspicious domains
- Installer with unusual digital signatures
- Downloads from newly registered domains

---

### 2. Execution
**Chokepoints Used:**
- User double-click execution
- MSI/NSIS installer execution
- DLL sideloading
- Browser extension installation

**Key Prerequisites:**
- User interaction
- Code execution permissions
- No AV/EDR blocking

**Detection Opportunity:**
- Unsigned executables from Downloads folder
- Browser processes spawning unusual children
- DLL loads from non-standard paths

---

### 3. Collection
**Chokepoints Used:**
- Browser credential stores (Chromium, Firefox)
- Windows Credential Manager
- Discord/Telegram tokens
- Cryptocurrency wallets
- Session cookies (auth bypass)
- SSH keys, VPN configs
- FTP client credentials

**Key Prerequisites:**
- File system access to browser profiles
- DPAPI access for encrypted credentials
- Memory access for running processes

**Detection Opportunity:**
- Access to browser SQLite databases
- DPAPI calls for credential decryption
- Unusual file reads in %APPDATA%
- Memory access to browser processes

---

### 4. Exfiltration
**Chokepoints Used:**
- HTTP/HTTPS POST to C2
- Telegram Bot API
- Discord webhooks
- Encrypted archives before exfil
- Cloud storage services (MEGA, Dropbox)

**Key Prerequisites:**
- Network connectivity
- C2 infrastructure
- Data staging location

**Detection Opportunity:**
- Outbound connections to unusual domains
- Large POST requests from non-browser processes
- Connections to Telegram/Discord APIs
- Compressed archive creation before network activity

---

### 5. Monetization (IAB Ecosystem)
**Result:**
- Credentials sold on dark web marketplaces
- Session tokens enable direct access
- Pre-mapped enterprise environments
- Leads to ransomware deployment

**Detection Opportunity (Downstream):**
- Unusual login from new geo-location
- Session token reuse detection
- Account behavior anomalies

---

## Common Infostealer Families

### RedLine
- **Distribution**: Malvertising, cracked software
- **Collection**: Browsers, crypto wallets, VPN configs
- **Exfiltration**: HTTP POST to C2
- **Active Since**: 2020
- **Prevalence**: Very High

### Vidar
- **Distribution**: Malvertising, YouTube descriptions
- **Collection**: Browsers, 2FA tokens, crypto wallets
- **Exfiltration**: HTTP POST, Telegram
- **Active Since**: 2018
- **Prevalence**: High

### Raccoon Stealer
- **Distribution**: Phishing, malvertising
- **Collection**: Browsers, email clients, crypto wallets
- **Exfiltration**: HTTP POST to C2
- **Active Since**: 2019
- **Prevalence**: High

### LummaC2
- **Distribution**: Malvertising, fake CAPTCHA pages
- **Collection**: Browsers, 2FA extensions, crypto wallets
- **Exfiltration**: HTTP POST with encryption
- **Active Since**: 2022
- **Prevalence**: Rising

### StealC
- **Distribution**: Malvertising, SEO poisoning
- **Collection**: Browsers, Discord, Telegram
- **Exfiltration**: HTTP POST to C2
- **Active Since**: 2023
- **Prevalence**: Rising

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

## Chokepoint Detection Strategy

### Collection Phase (Highest Value)
**Why it matters:** Preventing collection prevents exfiltration

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
**Why it matters:** Prevents credential compromise

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
**Why it matters:** Stops before collection begins

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
- Ransomware operators skip initial access phase
- Defenders face pre-authenticated attackers
- MFA bypass via session token theft

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
- Average listing price: $5K-$100K
- Time from infection to sale: 7-14 days

---

## Defense Strategy

### Prevention
- User awareness (fake software sites)
- Application allowlisting
- Browser isolation for downloads
- EDR with behavior detection

### Detection
- Monitor browser credential file access
- Alert on unusual network exfiltration
- Detect unsigned executables from Downloads
- Behavioral analytics on browser processes

### Response
- Immediate password resets if detected
- Revoke all session tokens
- Assume full credential compromise
- Hunt for follow-on activity (IAB → ransomware)

---

## References

- [HudsonRock Infostealer Data](https://www.hudsonrock.com/)
- [RedCanary Threat Detection Report](https://redcanary.com/)
- MITRE ATT&CK: T1555 (Credentials from Password Stores)
- MITRE ATT&CK: T1539 (Steal Web Session Cookie)
- [Cyberint IAB Analysis](https://cyberint.com/)

## Related Attack Chains

- [Ransomware](./ransomware.md) - Often follows infostealer-provided access
