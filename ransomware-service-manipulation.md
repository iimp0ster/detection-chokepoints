# Ransomware Defense Evasion - T1562.001 / T1489

**Last Updated:** 2025-01-15  
**Contributors:** Tyler

## Scope

**Tactics:** Defense Evasion, Impact  
**Techniques:** T1562.001 (Disable/Modify Tools), T1489 (Service Stop)  
**Scope:** Multi-tactic (Defense Evasion + Impact preparation)

Ransomware operators disable security tools, backup services, and databases before encryption to maximize impact.

## Variations

| Ransomware Family | First Seen | Status | Targeted Services |
|-------------------|------------|--------|-------------------|
| BlackBasta | 2022 | Active | AV, EDR, Veeam, SQL |
| Alphv/BlackCat | 2021 | Active | Sophos, Defender, VSS, SQL |
| Akira | 2023 | Active | Defender, backup agents |
| Qilin | 2024 | Active | EDR, Veeam, databases |
| LockBit 3.0 | 2022 | Active | AV, backup, ESXi services |

## Prerequisites (The Chokepoint)

What **must** be true for this technique to work:

- [x] Admin/SYSTEM privileges on target
- [x] Ability to query running services
- [x] Ability to stop/delete services
- [x] Target services must be running (to be stopped)

**Critical Conditions:**
- Service manipulation requires elevated privileges
- Cannot encrypt/exfiltrate effectively without disabling defenses
- Service stop pattern precedes encryption activity
- Often uses network logon for remote systems

## Evolution Timeline

### 2024-06 - ESXi Targeting Increase
- **Event:** Ransomware groups focus on ESXi hypervisors
- **Change:** VM-based service disruption vs. endpoint services
- **Detection Impact:** Need ESXi-specific logging and detection
- **The Constant:** Service enumeration → stop → delete pattern

### 2023-10 - Backup Service Priority
- **Event:** Explicit targeting of Veeam, Acronis, Windows Backup
- **Change:** Faster focus on backup prevention
- **Detection Impact:** Backup service monitoring becomes critical
- **The Constant:** Service enumeration → stop → delete pattern

### 2022-08 - Multi-Vendor EDR Evasion
- **Event:** Kill lists expand to 50+ security products
- **Change:** Comprehensive defense evasion vs. targeted
- **Detection Impact:** Cannot rely on specific product names
- **The Constant:** Service enumeration → stop → delete pattern

### 2021-05 - SQL/Database Targeting
- **Event:** Database services added to kill lists
- **Change:** Prevent transaction logs, ensure file locks released
- **Detection Impact:** Database service monitoring required
- **The Constant:** Service enumeration → stop → delete pattern

## Detection Strategy

### Research Level
**Goal:** Identify service stop patterns for security products

**Log Sources:**
- Windows System Event Log 7036 (Service State Change)
- Windows System Event Log 7040 (Service Start Type Change)

**Detection Logic:**
```
Event ID: 7036
Service: Contains "sophos" OR "defender" OR "veeam" OR "backup"
State: stopped
```

**Expected FP Rate:** High (legitimate maintenance, updates)  
**Use Case:** Baseline service stop frequency and patterns

### Hunt Level
**Goal:** Detect service stop + delete combinations

**Log Sources:**
- Windows System Event Log 7036 (Service State Change)
- Windows System Event Log 7045 (Service Install - includes delete)
- Sysmon Event ID 1 (Process Creation - sc.exe usage)

**Detection Logic:**
```
Process: sc.exe OR net.exe OR powershell.exe
CommandLine: "stop" AND (service name contains security/backup keywords)
Time Correlation: Service delete within 60 seconds
OR
Multiple services stopped in rapid succession (>3 in 5 minutes)
```

**Expected FP Rate:** Medium  
**Use Case:** Hunt for defense evasion campaigns

### Analyst Level
**Goal:** High-fidelity ransomware preparation detection

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Windows Security Event Log 4624 (Logon)
- Windows System Event Log 7036 (Service State)
- Windows System Event Log 7040/7045 (Service Config)

**Detection Logic:**
```
Network Logon (4624, LogonType 3) OR Local Admin
+ Process: sc.exe OR net.exe OR taskkill.exe
+ Service Stops: Multiple security/backup services
  - Sophos File Scanner (SophosFileScanner)
  - Windows Defender (WinDefend)
  - Veeam services (Veeam*)
  - SQL services (MSSQL*)
+ Service Delete: Attempted within 2 minutes
+ Pattern: 5+ services in 10 minute window
+ Context: After-hours OR unusual source IP
```

**Expected FP Rate:** Low  
**Use Case:** SOC alerting, ransomware pre-encryption detection

## Sigma Rules

- [Research Level Rule](./sigma-rules/ransomware-service-stop-research.yml)
- [Hunt Level Rule](./sigma-rules/ransomware-service-stop-hunt.yml)
- [Analyst Level Rule](./sigma-rules/ransomware-service-stop-analyst.yml)

## Common Target Services

**Security Products:**
- Sophos: SophosFileScanner, SAVService, Sophos Agent
- Windows Defender: WinDefend, Sense
- Generic AV: *antivirus*, *security*

**Backup Solutions:**
- Veeam: Veeam*, VeeamDeploymentService
- Windows: VSS, wbengine
- Acronis: *acronis*

**Databases:**
- SQL Server: MSSQL*, SQLWriter
- MySQL: MySQL*
- PostgreSQL: postgresql*

## OSINT Sources

**Ransomware Analysis:**
- Monitor ransomware leak sites for new families
- Analyze ransomware samples for service kill lists
- Track Kaspersky/Mandiant ransomware TTPs reports

**References:**
- [Kaspersky: Common TTPs of Modern Ransomware](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf)

## Known Bypasses

| Bypass Method | Mitigation | Detection |
|---------------|------------|-----------|
| Tamper protection enabled | Requires kernel-level access first | Detect kernel driver loading |
| Safe Mode boot | N/A - services don't start | Detect safe mode boots on servers |
| Service rename before stop | Allowlist by service binary path | Monitor service config changes |
| Process termination instead | Protected process light (PPL) | Monitor process termination events |

## References

- [MITRE T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE T1489](https://attack.mitre.org/techniques/T1489/)
- [Kaspersky Ransomware TTPs](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/06/23093553/Common-TTPs-of-the-modern-ransomware_low-res.pdf)

## Related Chokepoints

- **Lateral Movement → Defense Evasion**: Often follows initial compromise
- **Defense Evasion → Impact**: Precedes encryption activity by minutes

---

**Detection Priority:** Critical  
**Threat Prevalence:** High (Standard ransomware TTP)  
**Detection Difficulty:** Low (Clear service manipulation patterns)
