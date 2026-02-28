# Example: Adding Impacket RDP Shadowing

**Scenario:** Impacket PR#2064 adds rdp_shadow.py for RDP session hijacking
**Date:** 2025-01-15
**Source:** https://github.com/fortra/impacket/pull/2064

This document shows the complete workflow for updating the repository with a new
threat capability. Total time: ~10 minutes.

---

## Step 1: Identify Existing Chokepoint

**Question:** Does this require a new chokepoint or does it fit an existing one?

**Analysis:**
- RDP shadowing = Remote Desktop Hijacking (T1563.002)
- Prerequisites: Admin/SYSTEM, RDP running, network access, target session
- **Conclusion:** Fits existing "Remote Execution Tools" chokepoint

---

## Step 2: Update the YAML Chokepoint Entry

**File:** `chokepoints/lateral-movement/remote-execution-tools.yml`

**Changes:**

```yaml
Variations:
  # ... existing entries ...
  - Name: Impacket (rdp_shadow.py added)
    FirstSeen: "2015"  # Tool first seen; module added 2025-01
    Status: Active
    Notes: >
      rdp_shadow.py (RDP session hijacking) added via PR#2064 in 2025-01.
      Joins psexec.py, smbexec.py, wmiexec.py, atexec.py, dcomexec.py.

EvolutionTimeline:
  # Add a new entry at the top (most recent first):
  - Date: "2025-01"
    Event: Impacket adds rdp_shadow.py (PR#2064)
    Change: Native RDP session hijacking capability added to Impacket suite
    DetectionImpact: Existing RDP session manipulation detection applies; no new rule needed
    TheConstant: "Admin creds + network access + remote execution primitive"
```

---

## Step 3: Update Trends

**File:** `trends/2025-q1.md`

Add to the "New Tool Capabilities" section:

```markdown
### Q1 2025 — Impacket RDP Shadowing
**Tool:** Impacket rdp_shadow.py
**Date:** 2025-01-15
**Impact:** Low (existing chokepoint coverage)

**Details:**
- PR#2064 adds native RDP session hijacking to Impacket lateral movement suite
- Same prerequisites as existing RDP hijacking tools
- No new chokepoint created

**Chokepoint:** [remote-execution-tools.yml](../chokepoints/lateral-movement/remote-execution-tools.yml)
```

---

## Step 4: Log in CHANGELOG

**File:** `CHANGELOG.md`

```markdown
## [2025-01-15]

### Added
- Impacket rdp_shadow.py variant to remote-execution-tools.yml Variations table
- Evolution timeline entry for Impacket RDP shadowing (PR#2064)
- Q1 2025 trends entry for new Impacket capability

### Notes
- Existing sigma rules remain valid; no sigma update needed
```

---

## Step 5: Sigma Rule Assessment

**Question:** Does this require a new sigma rule or update to existing?

**Analysis:**
- RDP hijacking detection already exists (Event ID 4624 LogonType 10 + session manipulation)
- Impacket rdp_shadow.py uses the same Windows RDP APIs
- **Conclusion:** No rule update needed. Existing `sigma-rules/remote-execution/analyst.yml` covers this.

**Document the decision:** Add a comment in the sigma rule:

```yaml
# 2025-01-15: Impacket rdp_shadow.py (PR#2064) covered by this rule.
# LogonType 10 (RemoteInteractive) + IPC$ access pattern applies.
# No rule update required.
```

---

## Key Takeaway

**The chokepoint remained stable.**

While Impacket added a new capability, the fundamental requirements didn't change:
- Still needs admin/SYSTEM privileges
- Still needs RDP service running (port 3389)
- Still needs network access to target
- Still manipulates RDP sessions (same detection surface)

This is why chokepoint-based detection is durable — tools evolve, chokepoints don't.

---

## Total Time: ~10 Minutes

**Files Modified:** 3
1. `chokepoints/lateral-movement/remote-execution-tools.yml`
2. `trends/2025-q1.md`
3. `CHANGELOG.md`

**Sigma Rules Modified:** 0 (existing coverage confirmed)
