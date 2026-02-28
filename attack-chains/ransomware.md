# Ransomware Attack Chain

**Last Updated:** 2025-01-15

## Overview

Modern ransomware operations follow a predictable pattern of chokepoints from initial
access through impact. Understanding these chokepoints enables defense-in-depth detection
strategies.

**Average Time to Ransom (TTR):** <24 hours (Mandiant M-Trends 2025)

## Attack Chain Chokepoints

```
Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact
     ↓                  ↓                    ↓                  ↓            ↓
 [User Action]     [Memory/Reg]        [Remote Services]   [Stop Services]  [Encrypt]
```

## Chokepoint Breakdown

### 1. Initial Access
**Chokepoints Used:**
- [Renamed RMM Tools](../chokepoints/initial-access/renamed-rmm-tools.yml)
- [ClickFix Techniques](../chokepoints/initial-access/clickfix-techniques.yml)
- Phishing with malicious attachments
- Exposed RDP/VPN services

**Key Prerequisites:**
- User interaction OR exposed service
- Network access to target
- Code execution capability

**Detection Opportunity:**
- Browser download + suspicious file names
- RDP from unusual geo-location
- Email gateway flagged attachments

---

### 2. Credential Access
**Chokepoints Used:**
- LSASS memory dumping
- SAM/SECURITY registry hive access
- Kerberoasting
- Password spraying

**Key Prerequisites:**
- Admin/SYSTEM for LSASS access
- Domain user for Kerberoasting
- Network access to DC for spraying

**Detection Opportunity:**
- LSASS process access (Sysmon Event ID 10)
- Registry hive export
- Unusual Kerberos TGS requests
- Failed authentication spikes

---

### 3. Lateral Movement
**Chokepoints Used:**
- [Remote Execution Tools](../chokepoints/lateral-movement/remote-execution-tools.yml)
- RDP lateral movement
- WMI/DCOM execution
- PsExec-style service creation

**Key Prerequisites:**
- Valid admin credentials
- Network access (445, 135, 3389)
- Remote execution capability
- Target services running

**Detection Opportunity:**
- Network logon Type 3 with service creation
- IPC$ share access patterns
- Multiple hosts accessed in short window
- Unusual admin account usage

---

### 4. Defense Evasion
**Chokepoints Used:**
- [Ransomware Service Manipulation](../chokepoints/defense-evasion/ransomware-service-manipulation.yml)
- EDR/AV disabling
- Backup service termination
- Database service shutdown

**Key Prerequisites:**
- Admin/SYSTEM privileges
- Ability to enumerate services
- Service stop/delete permissions

**Detection Opportunity:**
- Multiple security services stopped
- Backup service termination
- Service deletion after stop
- sc.exe / net.exe usage patterns

---

### 5. Impact
**Chokepoints Used:**
- Volume Shadow Copy deletion
- File encryption
- Data exfiltration
- Ransom note deployment

**Key Prerequisites:**
- File system access
- Encryption library/capability
- Network for C2/exfil (optional)

**Detection Opportunity:**
- vssadmin delete shadows
- Mass file modifications
- High entropy file creation
- Ransom note .txt creation

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

## Common Ransomware Families

### BlackBasta
- **Initial Access**: Phishing, QakBot
- **Lateral Movement**: PsExec, Cobalt Strike
- **Evasion**: Sophos, Defender termination
- **Avg TTR**: 6-12 hours

### Alphv/BlackCat
- **Initial Access**: Compromised credentials, exposed services
- **Lateral Movement**: PsExec, RDP
- **Evasion**: Multi-vendor EDR killing
- **Avg TTR**: 4-8 hours

### Akira
- **Initial Access**: VPN compromise, RDP
- **Lateral Movement**: RDP lateral movement
- **Evasion**: Defender disabling
- **Avg TTR**: 8-16 hours

### LockBit 3.0
- **Initial Access**: RMM tools, RDP
- **Lateral Movement**: PsExec, Group Policy
- **Evasion**: Comprehensive service killing
- **Avg TTR**: 3-6 hours

---

## Detection Strategy

### Layer 1: Initial Access (Prevent Entry)
- Email gateway filtering
- Browser isolation
- User awareness training
- RMM tool allowlisting

### Layer 2: Credential Theft (Limit Blast Radius)
- LSASS protection (PPL, Credential Guard)
- Restricted admin mode
- LAPS for local admin passwords
- MFA enforcement

### Layer 3: Lateral Movement (Contain Spread)
- Network segmentation
- SMB signing enforcement
- Admin account monitoring
- Privilege access management

### Layer 4: Defense Evasion (Maintain Visibility)
- Tamper protection on EDR
- Protected backup infrastructure
- Service stop monitoring
- Immutable logging

### Layer 5: Impact (Last Resort)
- Offline/immutable backups
- File integrity monitoring
- Volume shadow copy protection
- Network-based encryption detection

---

## Key Metrics

**Detection Windows:**
- Initial Access → Lateral Movement: 2-6 hours
- Lateral Movement → Defense Evasion: 30 minutes - 2 hours
- Defense Evasion → Impact: 15-45 minutes

**Critical Detection Points:**
1. Credential dumping (highest value)
2. Lateral movement patterns (prevent spread)
3. Service manipulation (last warning before encryption)

---

## References

- [Mandiant M-Trends 2025](https://www.mandiant.com/m-trends)
- [Kaspersky: Common TTPs of Modern Ransomware](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf)
- MITRE ATT&CK: Ransomware Techniques

## Related Attack Chains

- [Infostealers](./infostealers.md) - Often precedes ransomware via IABs
