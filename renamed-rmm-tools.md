# Renamed RMM Tools - T1219

**Last Updated:** 2025-01-15  
**Contributors:** Tyler

## Scope

**Tactics:** Initial Access, Command & Control  
**Techniques:** T1219 (Remote Access Software)  
**Scope:** Spans multiple tactics (Initial Access → C2)

Legitimate remote management tools renamed/masqueraded to appear as trusted applications for initial access and persistent C2.

## Variations

| Tool | First Seen | Status | Common Masquerade Names |
|------|------------|--------|-------------------------|
| AnyDesk | 2020 | Declining | invoice.exe, tax_form.exe, SSN_verification.exe |
| ScreenConnect | 2022 | Active | support_tool.exe, IT_access.exe |
| TeamViewer | 2019 | Active | update.exe, system_check.exe |
| UltraViewer | 2023 | Active | security_scan.exe, verify.exe |
| RustDesk | 2024 | Emerging | remote_support.exe |
| RMM deploying RMM | 2024 | Active | ScreenConnect drops AnyDesk |

## Prerequisites (The Chokepoint)

What **must** be true for this technique to work:

- [x] Site to host payload (compromised or attacker-controlled)
- [x] Social engineering pretext (tax, invoice, SSN, IT support)
- [x] RMM tool binary (legitimate software, just renamed)
- [x] User interaction to download and execute

**Critical Conditions:**
- Browser download is the common delivery vector
- File masquerading (legitimate tool, deceptive name)
- User execution required
- Outbound connection to RMM infrastructure

## Evolution Timeline

### 2024-11 - RMM-to-RMM Deployment
- **Event:** Attackers using one RMM to deploy second RMM
- **Change:** Persistence technique - if one gets removed, backup exists
- **Detection Impact:** Process creation chain detection required
- **The Constant:** Browser download → renamed binary → outbound connection

### 2024-08 - RustDesk Emergence
- **Event:** Open-source RMM adoption increases
- **Change:** Self-hosted infrastructure, harder to blocklist
- **Detection Impact:** Cannot rely on known RMM domains/IPs
- **The Constant:** Browser download → renamed binary → outbound connection

### 2023-06 - UltraViewer Campaigns
- **Event:** Shift from AnyDesk to less-known tools
- **Change:** Evading AnyDesk-specific detections/blocks
- **Detection Impact:** Tool-agnostic detection becomes critical
- **The Constant:** Browser download → renamed binary → outbound connection

### 2022-01 - ScreenConnect Adoption
- **Event:** ConnectWise ScreenConnect becomes primary tool
- **Change:** More "professional" appearing tool
- **Detection Impact:** No change to core pattern
- **The Constant:** Browser download → renamed binary → outbound connection

## Detection Strategy

### Research Level
**Goal:** Identify all RMM tools in environment

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Application inventory logs

**Detection Logic:**
```
Process Name: anydesk.exe OR screenconnect*.exe OR teamviewer.exe OR ultraviewer.exe OR rustdesk.exe
```

**Expected FP Rate:** High (legitimate RMM usage)  
**Use Case:** Asset inventory, baseline legitimate usage

### Hunt Level
**Goal:** Detect RMM tools downloaded via browser

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 11 (File Creation)
- Browser download telemetry

**Detection Logic:**
```
File Created: *.exe
Parent Process: chrome.exe OR firefox.exe OR msedge.exe OR iexplore.exe
File Path: \Downloads\ OR \Temp\
Process Start: Within 5 minutes of download
Known RMM: Product metadata matches RMM vendors
```

**Expected FP Rate:** Medium  
**Use Case:** Hunt for user-initiated RMM downloads

### Analyst Level
**Goal:** Detect masqueraded RMM tools matching campaign themes

**Log Sources:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 11 (File Creation)  
- Sysmon Event ID 3 (Network Connection)
- File metadata analysis

**Detection Logic:**
```
File Created: *.exe
Parent Process: [browser]
File Name: Contains "tax" OR "invoice" OR "SSN" OR "SSA" OR "support" OR "verify"
File Metadata: OriginalFilename = "anydesk.exe" (but renamed)
OR File Signature: Matches known RMM vendor
Network: Outbound connection within 2 minutes
User Context: Standard user (not IT staff)
```

**Expected FP Rate:** Low  
**Use Case:** SOC alerting, campaign detection

## Sigma Rules

- [Research Level Rule](./sigma-rules/renamed-rmm-research.yml)
- [Hunt Level Rule](./sigma-rules/renamed-rmm-hunt.yml)
- [Analyst Level Rule](./sigma-rules/renamed-rmm-analyst.yml)

## OSINT Sources

**URLScan Queries:**
- `filename:tax*.exe OR filename:invoice*.exe`
- `page.domain:*anydesk* AND filename:*.exe`

**Shodan/Censys:**
- `product:"ScreenConnect"` - Find exposed instances
- `ssl:"AnyDesk"` - Identify infrastructure

**Threat Intel:**
- Monitor RMM vendor abuse reports
- Track campaign-specific file naming patterns

## Known Bypasses

| Bypass Method | Mitigation | Detection |
|---------------|------------|-----------|
| Legitimate business use | Allowlist known IT RMM instances | Focus on user-initiated downloads |
| Self-hosted RMM infrastructure | N/A | Detect by behavior, not domain |
| Legitimate file names | User training | Combine with file metadata mismatch |
| Delayed execution | N/A | Extend correlation time window |

## References

- [MITRE T1219](https://attack.mitre.org/techniques/T1219/)
- Campaign reporting (varies by quarter)

## Related Chokepoints

- **Initial Access → Persistence**: RMM provides both initial foothold and persistent access
- **Defense Evasion**: Legitimate signed binaries evade many security tools

---

**Detection Priority:** High  
**Threat Prevalence:** High (Common in phishing campaigns)  
**Detection Difficulty:** Medium (Requires metadata analysis)
