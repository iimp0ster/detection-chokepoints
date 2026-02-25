# Remote Execution Tools - T1021.002 / T1021.006

**Last Updated:** 2025-01-15  
**Contributors:** Tyler

## Scope

**Tactics:** Lateral Movement  
**Techniques:** T1021.002 (SMB/Windows Admin Shares), T1021.006 (Windows Remote Management)  
**Scope:** Single tactic, multiple remote service techniques

Offensive security tools used for remote code execution across Windows environments.

## Variations

| Tool/Suite | First Seen | Status | Primary Protocols |
|------------|------------|--------|-------------------|
| Impacket | 2015 | Active | SMB, WMI, RPC |
| CrackMapExec | 2016 | Active | SMB, WMI, WinRM, MSSQL |
| NetExec | 2023 | Active | SMB, WMI, WinRM, LDAP, SSH |
| Evil-WinRM | 2019 | Active | WinRM |
| Metasploit psexec | 2007 | Active | SMB |

**Impacket Modules:**
- psexec.py (SMB service creation)
- smbexec.py (SMB + scheduled tasks)
- wmiexec.py (WMI process creation)
- atexec.py (Task Scheduler)
- dcomexec.py (DCOM)
- rdp_shadow.py (RDP hijacking) - Added 2025-01

## Prerequisites (The Chokepoint)

What **must** be true for this technique to work:

- [x] Valid admin credentials for target system
- [x] Network access to target (SMB 445, WMI 135, RPC 135/139)
- [x] Remote execution capability (service creation, WMI, scheduled task)
- [x] Target service must be running (Server/Workstation service for SMB)

**Critical Conditions:**
- Network logon with admin privileges (LogonType 3)
- Service/process creation on remote system
- Cannot bypass credential + network access requirements

## Evolution Timeline

### 2025-01 - Impacket RDP Shadowing
- **Event:** Impacket PR#2064 adds rdp_shadow.py
- **Change:** Native RDP session hijacking capability
- **Detection Impact:** Existing RDP session manipulation detection applies
- **The Constant:** Admin creds + network access + remote execution

### 2023-08 - NetExec Fork
- **Event:** CrackMapExec forked to NetExec
- **Change:** Active development, new features, better OPSEC
- **Detection Impact:** No fundamental change to network behaviors
- **The Constant:** Admin creds + network access + remote execution

### 2019-05 - Evil-WinRM Release
- **Event:** Dedicated WinRM exploitation tool
- **Change:** Simplified WinRM-specific lateral movement
- **Detection Impact:** WinRM authentication spike detection needed
- **The Constant:** Admin creds + network access + remote execution

### 2016-01 - CrackMapExec Release
- **Event:** Multi-protocol lateral movement framework
- **Change:** Combined reconnaissance + exploitation
- **Detection Impact:** Requires detection across multiple protocols
- **The Constant:** Admin creds + network access + remote execution

## Detection Strategy

### Research Level
**Goal:** Identify any remote service execution patterns

**Log Sources:**
- Windows Security Event Log 4624 (Logon)
- Windows Security Event Log 4688 (Process Creation)
- Windows Security Event Log 7045 (Service Install)

**Detection Logic:**
```
Event ID: 4624
LogonType: 3 (Network)
Account: Admin privileges
Time Correlation: Service creation within 60 seconds
```

**Expected FP Rate:** High (legitimate admin activity)  
**Use Case:** Baseline admin behavior, identify normal patterns

### Hunt Level
**Goal:** Focus on suspicious service/process creation patterns

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Windows Security Event Log 4624 (Logon)
- Windows Security Event Log 4697 (Service Install)
- Windows Security Event Log 7045 (Service Install)

**Detection Logic:**
```
Network Logon (4624, LogonType 3)
+ Service Creation: Random name OR unusual path
OR
+ Process Creation: Parent = wmiprvse.exe OR services.exe
+ File Path: \Windows\Temp\ OR \ProgramData\ OR unusual locations
```

**Expected FP Rate:** Medium  
**Use Case:** Hunt for lateral movement campaigns

### Analyst Level
**Goal:** High-fidelity remote execution detection

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 3 (Network Connection)
- Windows Security Event Log 4624 (Logon)
- Windows Security Event Log 4697/7045 (Service)
- Windows Object Access Event ID 5145 (File Share)

**Detection Logic:**
```
Network Logon (4624, LogonType 3)
+ IPC$ share access (5145)
+ Service creation with suspicious characteristics:
  - Random 8-10 char name
  - Binary in \Windows\Temp\ or \Users\Public\
  - Runs cmd.exe or powershell.exe
+ Source IP: Internal lateral movement pattern
+ Time: Multiple hosts within short window (spray pattern)
```

**Expected FP Rate:** Low  
**Use Case:** SOC alerting, active lateral movement

## Sigma Rules

- [Research Level Rule](./sigma-rules/remote-exec-research.yml)
- [Hunt Level Rule](./sigma-rules/remote-exec-hunt.yml)
- [Analyst Level Rule](./sigma-rules/remote-exec-analyst.yml)

## Yara Rules

```yara
rule Impacket_Indicators
{
    meta:
        description = "Detects Impacket tool artifacts"
        author = "Tyler"
    strings:
        $s1 = "impacket" ascii nocase
        $s2 = "psexec.py" ascii
        $s3 = "wmiexec.py" ascii
        $s4 = "smbexec.py" ascii
    condition:
        any of them
}
```

## OSINT Sources

**Shodan/Censys:**
- `port:445 country:"US"` - SMB exposure
- `port:5985 product:"Microsoft HTTPAPI"` - WinRM exposure

**GitHub:**
- Monitor Impacket/NetExec/CME repositories for new features
- Track community tool development

## Known Bypasses

| Bypass Method | Mitigation | Detection |
|---------------|------------|-----------|
| Legitimate service names | Allowlist known services | Focus on service creation pattern + file path |
| Delayed execution | N/A | Extend correlation window |
| Credential stuffing | MFA, LAPS | Detect authentication patterns |
| NTLM relay | SMB signing, LDAP signing | Network-based relay detection |

## References

- [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE T1021.006](https://attack.mitre.org/techniques/T1021/006/)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [NetExec GitHub](https://github.com/Pennyw0rth/NetExec)
- [SOC Investigation: Event ID 5145](https://www.socinvestigation.com/threat-hunting-with-eventid-5145-object-access-detailed-file-share/)

## Related Chokepoints

- **Credential Access → Lateral Movement**: Stolen creds enable this technique
- **Defense Evasion**: Often paired with EDR/AV disabling

---

**Detection Priority:** High  
**Threat Prevalence:** High (Common in red teams and ransomware)  
**Detection Difficulty:** Medium (Requires correlation)
