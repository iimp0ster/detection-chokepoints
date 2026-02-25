# ClickFix Techniques - T1204.001 / T1204.003

**Last Updated:** 2025-01-15  
**Contributors:** Tyler

## Scope

**Tactics:** Initial Access  
**Techniques:** T1204.001 (Malicious Link), T1204.003 (Malicious Image)  
**Scope:** Single tactic, multiple user execution techniques

Social engineering attacks that trick users into copying and executing malicious commands via clipboard manipulation.

## Variations

| Method/Tool | First Seen | Status | Notes |
|-------------|------------|--------|-------|
| ClickFix | 2024-Q2 | Active | Original variant |
| FileFix | 2024-Q3 | Active | File-based execution |
| TerminalFix | 2024-Q4 | Active | Terminal/PowerShell focus |
| DownloadFix | 2024-Q4 | Active | Direct download execution |

## Prerequisites (The Chokepoint)

What **must** be true for this technique to work:

- [x] Host malicious site or compromised legitimate site
- [x] User must interact with clipboard (copy action)
- [x] User must paste and execute the copied content
- [x] Scripting interpreter available (PowerShell, cmd, bash)

**Critical Conditions:**
- User action required - cannot be fully automated
- Clipboard interaction is the pivot point
- Execution via scripting interpreter (powershell.exe, cmd.exe, bash, etc.)

## Evolution Timeline

### 2024-12 - DownloadFix Variant
- **Event:** Direct download execution methods emerge
- **Change:** Simplified payload delivery, less obfuscation needed
- **Detection Impact:** Same clipboard interaction, same execution pattern
- **The Constant:** User clipboard → script execution → network connection

### 2024-10 - TerminalFix Variant
- **Event:** Focus shifted to terminal-based execution prompts
- **Change:** UI mimics terminal windows, targets IT-savvy users
- **Detection Impact:** No change - still scripting interpreter execution
- **The Constant:** User clipboard → script execution → network connection

### 2024-08 - FileFix Variant
- **Event:** File download/execution variant introduced
- **Change:** Added file-based persistence before execution
- **Detection Impact:** Additional file creation telemetry available
- **The Constant:** User clipboard → script execution → network connection

### 2024-06 - ClickFix Original
- **Event:** Initial campaign observed
- **Change:** New social engineering technique
- **Detection Impact:** New pattern requiring detection development
- **The Constant:** User clipboard → script execution → network connection

## Detection Strategy

### Research Level
**Goal:** Identify any scripting interpreter making outbound connections

**Log Sources:**
- Windows Security Event Log (Process Creation)
- Network connection logs
- DNS logs

**Detection Logic:**
```
Process: powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe
Network: External connection initiated
Parent: ANY
```

**Expected FP Rate:** High  
**Use Case:** Baseline understanding, threat research

### Hunt Level
**Goal:** Focus on browser/explorer as parent process

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 3 (Network Connection)
- DNS query logs

**Detection Logic:**
```
Process: powershell.exe OR cmd.exe
Parent Process: explorer.exe OR chrome.exe OR firefox.exe OR msedge.exe
Network: External connection within 60 seconds
```

**Expected FP Rate:** Medium  
**Use Case:** Proactive hunting, user-initiated script execution detection

### Analyst Level
**Goal:** High-fidelity detection for SOC alerting

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 3 (Network Connection)
- Sysmon Event ID 22 (DNS Query)
- Parent process chain analysis

**Detection Logic:**
```
Process: powershell.exe OR cmd.exe
Parent: explorer.exe OR [browser]
CommandLine: Contains encoded commands OR obfuscation patterns
Network: External connection to newly registered domain OR low-reputation IP
Time: Connection within 30 seconds of process start
User Context: Interactive logon session
```

**Expected FP Rate:** Low  
**Use Case:** Automated alerting, immediate IR response

## Sigma Rules

- [Research Level Rule](./sigma-rules/clickfix-research.yml)
- [Hunt Level Rule](./sigma-rules/clickfix-hunt.yml)
- [Analyst Level Rule](./sigma-rules/clickfix-analyst.yml)

## OSINT Sources

**URLScan Queries:**
- `page.url:*clickfix* OR page.url:*filefix*`
- Search for clipboard manipulation JavaScript

**Threat Intel:**
- [ClickGrab Database](https://mhaggis.github.io/ClickGrab/)
- [AITMFEED ClickFix Infrastructure Tracking](https://www.aitmfeed.com/blog/blog-1/tracking-clickfix-infrastructure-4)

## Known Bypasses

| Bypass Method | Mitigation | Detection |
|---------------|------------|-----------|
| Legitimate script hosting | User awareness training | Focus on execution context, not hosting |
| Clipboard obfuscation | N/A - user still executes | Detect execution patterns, not clipboard content |
| Delayed execution | N/A | Extend time window in correlation logic |

## References

- [Huntress: Don't Sweat ClickFix](https://huntress.com/blog/dont-sweat-clickfix-techniques)
- [ClickGrab Intelligence](https://mhaggis.github.io/ClickGrab/)
- [MITRE T1204.001](https://attack.mitre.org/techniques/T1204/001/)

## Related Chokepoints

- **Initial Access → Execution**: User-initiated script execution is the bridge
- **Command & Control**: Network connections often follow immediately

---

**Detection Priority:** High  
**Threat Prevalence:** High (Active campaigns)  
**Detection Difficulty:** Low (Clear execution patterns)
