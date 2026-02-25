# Chokepoint Identification Framework

## Core Principle

**If an attacker wants to achieve objective X, they must satisfy conditions Y.**

Chokepoints are the Y conditions that cannot be bypassed regardless of tool choice.

## Identification Methodology

### 1. Start with the Objective

What does the attacker need to accomplish?
- Gain initial access?
- Move laterally?
- Evade defenses?
- Exfiltrate data?

### 2. Identify Required Components

For the objective to succeed, what **must** be true?

**Example - Lateral Movement via SMB:**
- Credentials with admin rights on target
- Network connectivity to target on 445/135/139
- SMB service running on target
- Ability to execute code remotely (service, scheduled task, WMI, etc.)

### 3. Map to MITRE ATT&CK

Which technique(s) does this cover?
- Single technique (T1021.002 - SMB/Windows Admin Shares)
- Multiple techniques (Credential Access + Lateral Movement + Execution)

### 4. Document Variations

What tools/methods achieve the same objective using this chokepoint?

**Example - Remote SMB Execution:**
- Impacket (psexec.py, smbexec.py)
- CrackMapExec
- NetExec
- Metasploit psexec modules
- Native PsExec.exe

All require the same prerequisites (the chokepoint), just different implementations.

### 5. Build Detection Iterations

Start broad, refine to production-ready:

**Research Level:**
```
Goal: Visibility into the chokepoint
Logic: Detect any usage of required components
FPs: High - includes legitimate activity
Use: Threat research, baseline understanding
```

**Hunt Level:**
```
Goal: Reduce noise, maintain coverage
Logic: Add context (parent process, user, timing)
FPs: Medium - some legitimate usage remains
Use: Active threat hunting, campaign detection
```

**Analyst Level:**
```
Goal: Production SOC deployment
Logic: High-fidelity indicators, correlated events
FPs: Low - minimal legitimate usage
Use: Automated alerting, IR escalation
```

## Chokepoint vs. Tool Detection

| Chokepoint Detection | Tool Detection |
|---------------------|----------------|
| Detects prerequisites | Detects specific tool |
| Survives tool evolution | Breaks when tool changes |
| Broad coverage | Narrow coverage |
| Higher initial FP rate | Lower initial FP rate |
| Long-term value | Short-term value |

**Example:**

**Tool Detection:**
- `CommandLine contains "psexec.exe"`
- Bypassed by: renaming, different tools (wmiexec, smbexec)

**Chokepoint Detection:**
- Service creation via network logon with suspicious binary paths
- Catches: psexec, wmiexec, smbexec, custom tools, future tools

## When Chokepoints Change

Rare, but happens when:

1. **New OS features** - Microsoft adding new authentication methods
2. **Protocol changes** - SMBv1 → SMBv2/3 requirements
3. **Defense forcing adaptation** - EDR blocking causes chokepoint shift

Document these in `threat-evolution/chokepoint-shifts.md`

## Common Chokepoint Categories

### Initial Access
- User interaction (click, download, execute)
- Exposed services (RDP, VPN, webmail)
- Supply chain trust relationships

### Credential Access
- Memory access (LSASS, SAM)
- Registry access (credential storage)
- Network traffic (cleartext protocols)

### Lateral Movement
- Authentication (valid credentials)
- Network access (open ports)
- Execution (service, task, registry)

### Defense Evasion
- Process/service manipulation (terminate, disable)
- Log manipulation (clear, disable)
- Privilege escalation (UAC bypass, token theft)

### Impact
- File encryption (ransomware)
- Service disruption (backups, databases)
- Data destruction

## Testing Your Chokepoint

Ask yourself:
1. Can an attacker achieve this objective without meeting these conditions? **No** = Valid chokepoint
2. Does this detection break if the tool changes? **No** = Good chokepoint
3. Does this cover multiple tool families? **Yes** = Strong chokepoint
4. Will this still work in 6-12 months? **Yes** = Durable chokepoint

## Anti-Patterns (Not Chokepoints)

- **Specific file hashes** - Too specific, bypassed instantly
- **Exact command lines** - Easily modified
- **Single tool signatures** - Breaks on tool evolution
- **IP addresses** - Infrastructure changes constantly

## Example Workflow

**Scenario:** New ransomware family "CryptoLocker2025"

**Bad Approach:**
```
Hunt for: CryptoLocker2025.exe
Result: Works until they rename it
```

**Chokepoint Approach:**
```
1. Objective: Encrypt files for ransom
2. Prerequisites:
   - Stop backup services (vss, backup agents)
   - Stop security tools (AV, EDR)
   - File encryption capability
   - Network for C2/exfil
3. Chokepoint: Service manipulation + mass file modifications
4. Detection: Service termination events + abnormal file activity
5. Coverage: All ransomware families, not just CryptoLocker2025
```

---

**Remember: Attackers change tools constantly. Prerequisites remain stable.**
