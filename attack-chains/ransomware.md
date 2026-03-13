---
layout: attack-chain
title: Ransomware Attack Chain
subtitle: "How ransomware operators all follow the same five-stage chokepoint sequence — regardless of group, brand, or tooling."
last_updated: 2025-01-15
permalink: /attack-chains/ransomware/

stages:
  - id: initial_access
    label: Initial Access
    detection_signals:
      - "Browser download of renamed/masqueraded binary (missing or mismatched signature)"
      - "RDP/VPN login from new geo-location or ASN"
      - "Email attachment execution from user Downloads folder"
    chokepoint_links:
      - label: "Renamed RMM Tools"
        slug: "renamed-rmm-tools"
      - label: "ClickFix Techniques"
        slug: "clickfix-techniques"
  - id: credential_access
    label: Credential Access
    detection_signals:
      - "LSASS process access by non-system process (Sysmon EID 10)"
      - "SAM/SECURITY registry hive read outside of system tools"
      - "Kerberos TGS-REQ spike for service accounts"
  - id: lateral_movement
    label: Lateral Movement
    detection_signals:
      - "Network logon Type 3 + service creation across multiple hosts in short window"
      - "IPC$ share access followed by ADMIN$ write"
      - "Unusual admin account authenticating to 5+ hosts within 30 minutes"
    chokepoint_links:
      - label: "Remote Execution Tools"
        slug: "remote-execution-tools"
  - id: defense_evasion
    label: Defense Evasion
    detection_signals:
      - "Multiple security/backup services stopped in rapid succession (sc.exe / net stop)"
      - "Security service deletion after stop"
      - "Veeam, VSS, or SQL service termination"
    chokepoint_links:
      - label: "Ransomware Service Manipulation"
        slug: "ransomware-service-manipulation"
  - id: impact
    label: Impact
    detection_signals:
      - "vssadmin delete shadows / wmic shadowcopy delete"
      - "Mass file modifications with high-entropy output (bulk file rename)"
      - "Ransom note .txt/.html creation across multiple directories"

actors:
  - name: BlackBasta
    status: Inactive
    initial_access: "QakBot / phishing email lure"
    credential_access: "LSASS dump + Kerberoasting"
    lateral_movement: "PsExec + Cobalt Strike beacon"
    defense_evasion: "Sophos / Defender stop via sc.exe"
    impact: "VSS delete + ChaCha20 file encrypt"
  - name: LockBit 3.0
    status: Disrupted
    initial_access: "Stolen RDP creds / exposed RMM"
    credential_access: "LSASS dump + SAM hive export"
    lateral_movement: "PsExec + GPO mass-deploy"
    defense_evasion: "Comprehensive service kill list (50+ services)"
    impact: "VSS delete + fastest-in-class encrypt"
  - name: Akira
    status: Active
    initial_access: "VPN compromise (no MFA / cred stuffing)"
    credential_access: "LSASS dump + credential file harvest"
    lateral_movement: "RDP hop + AnyDesk"
    defense_evasion: "Defender disable via PowerShell"
    impact: "VSS delete + dual-extension encrypt"
  - name: Alphv/BlackCat
    status: Defunct
    initial_access: "Stolen creds / exposed web services"
    credential_access: "LSASS dump + AD enumeration (BloodHound)"
    lateral_movement: "PsExec + RDP + WMI"
    defense_evasion: "Multi-vendor EDR termination (Impacket)"
    impact: "VSS delete + cross-platform Rust encrypt"
  - name: Play
    status: Active
    initial_access: "N-day exploits (FortiOS, Exchange ProxyNotShell)"
    credential_access: "LSASS dump + Kerberoasting"
    lateral_movement: "PsExec + WMI lateral movement"
    defense_evasion: "AV/EDR service termination"
    impact: "VSS delete + selective file encrypt"

chokepoints:
  initial_access: "User executes payload OR exposed service is network-reachable"
  credential_access: "Elevated process reads memory/registry containing credential material"
  lateral_movement: "Valid admin credentials + network path open (445 / 3389 / 135)"
  defense_evasion: "SYSTEM-level process with service stop/delete permission"
  impact: "File system write access + encryption library loaded"
---

# Ransomware Attack Chain

## Overview

Modern ransomware operations follow a predictable pattern of chokepoints from initial
access through impact. Understanding these chokepoints enables defense-in-depth detection
strategies that catch any actor regardless of tooling.

**Average Time to Ransom (TTR):** <24 hours (Mandiant M-Trends 2025)

---

## Example: BlackBasta Ransomware

### Timeline
```
T+0:00  - Phishing email with QakBot attachment
T+0:15  - QakBot C2 established, credential theft begins
T+2:00  - Cobalt Strike beacon deployed
T+4:00  - Network reconnaissance, domain admin creds obtained
T+6:00  - Lateral movement to 15 systems via PsExec
T+6:30  - EDR/AV services stopped across environment
T+6:45  - Veeam backup server compromised, backups deleted
T+7:00  - File encryption begins
T+7:30  - Ransom note deployed, TTR = 7.5 hours
```

### Chokepoints Hit
1. **Initial Access**: Email attachment execution
2. **Credential Access**: LSASS dumping, Kerberoasting
3. **Lateral Movement**: PsExec service creation (445/TCP)
4. **Defense Evasion**: Service termination (sc.exe)
5. **Impact**: VSS deletion, file encryption

### Detection Opportunities
- **T+0:15**: Unusual outbound connections from user workstation
- **T+2:00**: Named pipe creation (Cobalt Strike beacon)
- **T+4:00**: Kerberos TGS-REQ spike
- **T+6:00**: Network logon Type 3 + service creation across multiple hosts
- **T+6:30**: Security service stop events
- **T+6:45**: Backup service termination
- **T+7:00**: Mass file entropy changes

---

## Key Metrics

**Detection Windows:**
- Initial Access → Lateral Movement: 2–6 hours
- Lateral Movement → Defense Evasion: 30 minutes – 2 hours
- Defense Evasion → Impact: 15–45 minutes

**Critical Detection Points:**
1. Credential dumping (highest value — stops spread before it starts)
2. Lateral movement patterns (contains blast radius)
3. Service manipulation (last warning before encryption)

---

## References

- [Mandiant M-Trends 2025](https://www.mandiant.com/m-trends)
- [Kaspersky: Common TTPs of Modern Ransomware](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf)
- MITRE ATT&CK: Ransomware Techniques

## Related Attack Chains

- [Infostealers](./infostealers.md) - Often precedes ransomware via IABs
