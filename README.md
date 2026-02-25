# Detection Chokepoints

**Strangle threats by detecting unavoidable actions, not specific tools.**

## What is a Chokepoint?

A chokepoint is a condition that **must** be met for an attack technique to succeed, regardless of the tool or threat actor. While attackers constantly evolve their tools (Cobalt Strike → Sliver → Mythic), the underlying requirements remain constant.

**Example**: Lateral movement always requires:
- Credentials (stolen, guessed, or default)
- Network access to target (445, 135, 3389, etc.)
- Execution capability (service creation, scheduled task, RDP, etc.)

Detect these requirements instead of specific tool signatures.

## Why Chokepoints Matter

- **Time = Money**: Dwell time decreased from weeks to hours due to RaaS/IAB ecosystems
- **Tool-Agnostic**: Detections survive tool migrations and obfuscation
- **Coverage**: One chokepoint detection covers multiple threat families
- **Future-Proof**: New tools still hit the same chokepoints

## Framework

Every chokepoint is documented using three dimensions:

| Scope | Variations | Prerequisites |
|-------|-----------|---------------|
| Which MITRE tactic(s)/technique(s)? | What variations exist? | What must be true for this to work? |
| Single technique or spans multiple? | Tool differences, evolution over time | The unchanging requirements |

## Detection Maturity Model

Chokepoint detections evolve through three stages:

1. **Research** - Broad visibility, high false positives, exploratory
2. **Hunt** - Refined logic, lower FPs, threat hunting ready
3. **Analyst** - Production-ready, minimal FPs, SOC-deployable

## Current Threat Trends

### 2025 Q1
- **RaaS TTR Compression**: Median dwell time now <24 hours (Mandiant M-Trends 2025)
- **Infostealer Proliferation**: IABs selling pre-mapped environments with valid creds
- **ClickFix Evolution**: FileFix → TerminalFix → DownloadFix (same chokepoint: clipboard + user execution)

### Hot Chokepoints
1. **Initial Access**: Renamed RMM tools, ClickFix variants
2. **Defense Evasion**: EDR/AV service manipulation, process termination
3. **Lateral Movement**: Remote services (SMB, RDP, WMI)
4. **Impact**: Backup/database service termination

## Repository Structure

```
chokepoints/          # Organized by MITRE tactic
attack-chains/        # Full kill chains (ransomware, infostealers)
threat-evolution/     # Yearly trends, chokepoint shifts
sigma-rules/          # Detection rules by technique
templates/            # Quick-add templates for new entries
```

## Quick Start

**Adding a New Threat Example:**
1. Identify which existing chokepoint(s) it uses
2. Update `chokepoints/[tactic]/[technique].md` with new variation
3. Add entry to `threat-evolution/[year]-trends.md`
4. Create/update sigma rule at appropriate maturity level
5. Log in `CHANGELOG.md`

**Creating a New Chokepoint:**
1. Use `templates/chokepoint-template.md`
2. Document scope, variations, prerequisites
3. Create detection iterations (research → hunt → analyst)
4. Add to relevant attack chains

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [ClickGrab Intelligence](https://mhaggis.github.io/ClickGrab/)
- [Mandiant M-Trends Reports](https://www.mandiant.com/m-trends)

## Contributing

This repo focuses on **detection engineering**, not threat intelligence feeds. Contributions should:
- Identify chokepoints (requirements), not just IOCs
- Show TTP evolution over time
- Provide actionable sigma/yara rules
- Demonstrate detection at multiple maturity levels

---

**Detection is a game of economics. Make it expensive for attackers to avoid your detections.**
