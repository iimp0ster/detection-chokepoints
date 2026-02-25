# Example: Adding Impacket RDP Shadowing

**Scenario:** Impacket PR#2064 adds rdp_shadow.py for RDP session hijacking  
**Date:** 2025-01-15  
**Source:** https://github.com/fortra/impacket/pull/2064

This document shows the complete workflow for updating the repository with this new threat capability.

---

## Step 1: Identify Existing Chokepoint

**Question:** Does this require a new chokepoint or fit existing one?

**Analysis:**
- RDP shadowing = Remote Desktop Hijacking (T1563.002)
- Prerequisites: Admin/SYSTEM, RDP running, network access, target session
- **Conclusion:** Fits existing "Remote Execution Tools" chokepoint

---

## Step 2: Update Chokepoint Document

**File:** `chokepoints/lateral-movement/remote-execution-tools.md`

**Changes:**

```markdown
## Variations

| Tool/Suite | First Seen | Status | Primary Protocols |
|------------|------------|--------|-------------------|
| Impacket | 2015 | Active | SMB, WMI, RPC |
...

**Impacket Modules:**
- psexec.py (SMB service creation)
- smbexec.py (SMB + scheduled tasks)
- wmiexec.py (WMI process creation)
- atexec.py (Task Scheduler)
- dcomexec.py (DCOM)
- rdp_shadow.py (RDP hijacking) - Added 2025-01  ← NEW LINE

## Evolution Timeline

### 2025-01 - Impacket RDP Shadowing  ← NEW SECTION
- **Event:** Impacket PR#2064 adds rdp_shadow.py
- **Change:** Native RDP session hijacking capability
- **Detection Impact:** Existing RDP session manipulation detection applies
- **The Constant:** Admin creds + network access + remote execution
```

---

## Step 3: Update Threat Evolution

**File:** `threat-evolution/2025-trends.md`

**Changes:**

```markdown
## New Tool Capabilities

### Q1 2025 - Impacket RDP Shadowing
**Tool:** Impacket rdp_shadow.py  
**Date:** 2025-01-15  
**Impact:** Low (existing chokepoint coverage)

**Details:**
- PR#2064 adds native RDP session hijacking
- Joins existing Impacket lateral movement suite
- Same prerequisites as other RDP hijacking methods

**Detection Impact:**
- Existing RDP session manipulation detections apply
- No new chokepoint created
- Monitor for adoption in Q2-Q3

**Chokepoint:** [Remote Execution Tools](../chokepoints/lateral-movement/remote-execution-tools.md)
```

---

## Step 4: Log in CHANGELOG

**File:** `CHANGELOG.md`

**Changes:**

```markdown
## [2025-01-15] - Impacket RDP Shadowing Update

### Added
- New tool capability: Impacket rdp_shadow.py (PR#2064)
- Updated remote-execution-tools.md with RDP shadowing variant
- Added Q1 2025 tool capability entry in threat evolution

### Updated
- Threat evolution 2025 trends with Impacket expansion
- Remote execution tools variations table
```

---

## Step 5: Sigma Rule Assessment

**Question:** Does this require new sigma rule or update existing?

**Analysis:**
- RDP hijacking detection already exists (Event ID 4624 LogonType 10 + session manipulation)
- Impacket tool uses same Windows APIs
- **Conclusion:** No rule update needed, existing coverage applies

**Documentation:**
Add note to `chokepoints/lateral-movement/remote-execution-tools.md`:

```markdown
## Detection Strategy

### Hunt Level
...
**Detection Logic:**
```
Network Logon (4624, LogonType 3)
+ Service creation with suspicious characteristics:
...
OR
+ RDP Session Hijacking (LogonType 10 + tscon/shadow commands)  ← Added note
```
```

---

## Total Time: ~10 Minutes

**Files Modified:** 3
1. `chokepoints/lateral-movement/remote-execution-tools.md`
2. `threat-evolution/2025-trends.md`
3. `CHANGELOG.md`

**Sigma Rules Modified:** 0 (existing coverage)

---

## Key Takeaway

**The chokepoint remained stable.** 

While Impacket added a new capability, the fundamental requirements didn't change:
- Still needs admin/SYSTEM privileges
- Still needs RDP service running
- Still needs network access to target
- Still manipulates RDP sessions (same detection surface)

This is why chokepoint-based detection is durable - tools evolve, chokepoints don't.
