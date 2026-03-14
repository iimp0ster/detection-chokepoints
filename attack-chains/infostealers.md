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

## References

- [HudsonRock Infostealer Data](https://www.hudsonrock.com/)
- [RedCanary Threat Detection Report](https://redcanary.com/)
- MITRE ATT&CK: T1555 (Credentials from Password Stores)
- MITRE ATT&CK: T1539 (Steal Web Session Cookie)
- [Cyberint IAB Analysis](https://cyberint.com/)

## Related Attack Chains

- [Ransomware](./ransomware.md) - Often follows infostealer-provided access
