# Quick-Add Template

Use this for rapidly adding new tool variants to existing chokepoints.

## New Variation Entry

**Chokepoint:** [Which existing chokepoint does this belong to?]  
**Tool/Method:** [Name of new tool/variant]  
**Date Identified:** YYYY-MM-DD  
**Status:** [Active/Emerging/Declining]

### What Changed
- [What's different from previous variants?]

### What Stayed the Same (The Chokepoint)
- [What prerequisites remain unchanged?]

### Detection Impact
- [ ] Existing detections still work
- [ ] Minor rule adjustment needed
- [ ] New detection pattern required

### Quick Detection Notes
```
[One-liner or simple detection logic]
```

### References
- [Link to PR/blog/analysis]
- [Threat intel source]

---

## Update Checklist

- [ ] Added to `chokepoints/[tactic]/[technique].md` variations table
- [ ] Updated evolution timeline in chokepoint doc
- [ ] Logged in `CHANGELOG.md`
- [ ] Updated `threat-evolution/[year]-trends.md` if significant
- [ ] Tested/updated sigma rule if needed
- [ ] Tagged related attack chains

---

## Example Entry

**Chokepoint:** Remote Desktop Hijacking  
**Tool/Method:** Impacket rdp_shadow.py  
**Date Identified:** 2025-01-15  
**Status:** Active

### What Changed
- Impacket suite now includes native RDP shadowing capability
- Previously required standalone tools or manual tscon commands

### What Stayed the Same (The Chokepoint)
- Still requires admin/SYSTEM privileges
- RDP service must be running (3389)
- Existing session to hijack must exist
- Network connectivity to target required

### Detection Impact
- [x] Existing detections still work
- [ ] Minor rule adjustment needed
- [ ] New detection pattern required

### Quick Detection Notes
```
Event ID 4624 (LogonType 10) + session manipulation commands
Same patterns as RDPInception, tscon.exe methods
```

### References
- https://github.com/fortra/impacket/pull/2064
