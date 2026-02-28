# Chokepoint Shifts

**Purpose:** Track when threat actors abandon one chokepoint for another due to defensive improvements.

**Last Updated:** 2025-01-15

---

## What is a Chokepoint Shift?

A chokepoint shift occurs when defensive measures make a chokepoint too costly or
risky, forcing attackers to migrate to alternative methods with different prerequisites.

**Example:**
- **Old Chokepoint:** Email macro execution (T1204.002)
- **Defensive Change:** Microsoft disables macros by default (2022)
- **New Chokepoint:** ISO/LNK file execution (T1204.001)
- **Result:** File type changed, but user execution requirement remains

**Key distinction:** Not all tool changes are chokepoint shifts.
- **Tool Rotation**: Same prerequisites, different tool → chokepoint detection still valid
- **True Shift**: Prerequisites change → detection logic must be updated

---

## Active Shifts (2024-2025)

### 1. RMM Tool Rotation (Not a True Shift)

**Observation:**
```
AnyDesk → ScreenConnect → RustDesk
```

**Classification:** Tool Rotation, NOT Chokepoint Shift
**Why:** Prerequisites unchanged (browser download, masquerading, user execution)

**Defensive Pressure:**
- AnyDesk blocking/detection increase
- Security vendor signatures mature
- User awareness of specific tool names

**Attacker Response:**
- Rotate to less-detected RMM tools
- Increase masquerading sophistication
- Adopt self-hosted solutions (RustDesk)

**Chokepoint Status:** Stable (browser download + user execution constant)
**Detection Adaptation:** Minimal (same detection logic applies)

---

### 2. Email Macros → Alternative File Types (True Shift)

**Timeline:**
- **2020-2022:** VBA macros in Office docs dominant
- **2022:** Microsoft disables macros by default
- **2022-2024:** Shift to ISO, LNK, CHM, HTML smuggling

**Old Chokepoint:**
```
Prerequisites:
- Email attachment delivery
- Macro execution enabled
- User clicks "Enable Macros"
```

**New Chokepoint:**
```
Prerequisites:
- Email attachment delivery
- Alternative file type (ISO, LNK)
- User double-click execution
- Scripting interpreter available
```

**Classification:** Partial Shift (delivery same, execution method different)

**Defensive Pressure:**
- Macro disable by default (Office 2022+)
- Mark of the Web (MotW) improvements
- Email gateway macro scanning

**Attacker Response:**
- ISO files (MotW bypass via mounted volumes)
- LNK files (direct script execution)
- HTML smuggling (client-side assembly)
- OneNote/PDF with embedded objects

**Chokepoint Evolution:**
- User execution still required ✓
- Email delivery still primary ✓
- File type flexibility increased ✗

**Detection Adaptation:** Moderate (new file types require new signatures)
**Current Status:** Ongoing evolution (attackers testing new file types)

---

### 3. LSASS Direct Access → Indirect Methods (Emerging)

**Timeline:**
- **2015-2023:** Direct LSASS process memory dumping
- **2023-2024:** Credential Guard, PPL deployment increases
- **2024-2025:** Shift to indirect methods emerging

**Old Chokepoint:**
```
Prerequisites:
- Admin/SYSTEM privileges
- Direct LSASS process access (SeDebugPrivilege)
- Memory dump capability
```

**New Chokepoint (Emerging):**
```
Prerequisites:
- Admin/SYSTEM privileges
- Kernel-level access OR alternative credential sources
- Methods: SAM/SECURITY hive, NTDS.dit, Kerberoasting
```

**Classification:** True Shift (prerequisites changing)

**Defensive Pressure:**
- Credential Guard adoption
- Protected Process Light (PPL) for LSASS
- EDR monitoring of LSASS access

**Attacker Response:**
- Bring Your Own Vulnerable Driver (BYOVD) for kernel access
- Increased use of Kerberoasting
- Registry hive extraction (SAM/SECURITY)
- NTDS.dit extraction from domain controllers

**Chokepoint Status:** Fragmenting (multiple alternatives emerging)
**Detection Adaptation:** Significant (must cover multiple credential sources)
**Current Status:** Early shift (LSASS still dominant, alternatives growing)

---

## Historical Shifts (2020-2024)

### SMB v1 → SMB v2/v3
**Years:** 2017-2020
**Trigger:** MS17-010 (EternalBlue) patches, SMBv1 deprecation

**Impact:**
- WannaCry/NotPetya-style worm propagation ended
- Attackers shifted to credential-based lateral movement
- Chokepoint changed from exploit-based to cred-based

**Detection Change:** Exploit detection → Credential theft detection

---

### RDP Brute Force → Credential Stuffing
**Years:** 2018-2023
**Trigger:** Network-based RDP brute force detection improvements

**Impact:**
- Shift from blind brute force to using stolen credentials
- Infostealer-harvested credentials used instead
- MFA bypass via session token theft

**Detection Change:** Failed logon monitoring → Geo-location anomaly detection

---

### PowerShell Downloads → LOLBins
**Years:** 2019-2022
**Trigger:** PowerShell AMSI, script block logging improvements

**Impact:**
- Shift from `Invoke-WebRequest` to certutil, bitsadmin, curl
- Same chokepoint (download + execute) different tools
- Categorization: Tool Rotation, not Chokepoint Shift

**Detection Change:** PowerShell-specific → Generic download behavior

---

## Predicted Shifts (2025-2026)

### Browser Credential Storage → Alternative Sources
**Likelihood:** Medium (40%)
**Timeline:** 2025-2026

**Trigger:**
- Increased EDR monitoring of browser database access
- OS-level credential store protections
- Password manager adoption

**Predicted Response:**
- Keylogging increase
- Network credential capture (MitM)
- Session token theft prioritized over passwords

**Detection Preparation:**
- Keylogger detection (keypress monitoring)
- Network traffic analysis (MitM detection)
- Session token abuse detection (geo/behavior anomalies)

---

### Local Execution → Cloud-Based C2
**Likelihood:** High (70%)
**Timeline:** 2025

**Trigger:**
- Endpoint security maturation
- Cloud infrastructure trust relationships
- Remote work normalization

**Predicted Response:**
- Abuse of legitimate cloud services (GitHub, Discord, Dropbox)
- Serverless C2 infrastructure
- Cloud-to-cloud lateral movement

**Detection Preparation:**
- Cloud service abuse detection
- API anomaly detection
- Cross-tenant activity monitoring

---

## Metrics

### Shift Velocity
**How quickly do attackers adapt to defensive changes?**

- **Tool Rotation:** 1-3 months
- **Minor Shift:** 6-12 months
- **Major Shift:** 12-24 months

### Shift Completeness
**What percentage of attackers adopt the new chokepoint?**

- **Email Macros → ISO/LNK:** 80% (high completeness)
- **LSASS → Alternatives:** 20% (early adoption)
- **RDP Brute Force → Cred Stuffing:** 60% (majority shift)

---

## Strategic Implications

### For Defenders

**When Detecting a Shift:**
1. Maintain detection of old chokepoint (attackers lag)
2. Develop detection for new chokepoint immediately
3. Overlap coverage for 12-24 months
4. Retire old detection only after <5% threat prevalence

**When Causing a Shift:**
1. Celebrate success (made attack more expensive)
2. Prepare for alternative chokepoints
3. Monitor for adaptation (usually 6-12 months)
4. Layer defenses (prevent single chokepoint reliance)

### For Detection Engineers

**Chokepoint Shift Indicators:**
- Declining alert volume on established detection
- New attack patterns in threat intel
- Tool diversity increase (fragmentation)
- Technique prevalence changes in MITRE ATT&CK mapping

**Response Strategy:**
- Monitor threat intel for shift signals
- Maintain detection across chokepoint variations
- Focus on upstream chokepoints (earlier in kill chain)
- Build flexibility into detection logic

---

## References

- Microsoft Security Intelligence Reports (yearly)
- Verizon DBIR (Data Breach Investigations Report)
- Mandiant M-Trends (yearly)
- Red Canary Threat Detection Report (yearly)

---

**Next Review:** 2025-07-15 (Mid-year assessment)
