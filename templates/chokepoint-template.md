# [Technique Name] — [MITRE ID]

> **Note:** This is the human-readable markdown template for documenting chokepoints.
> For the canonical machine-parseable format, use the YAML template in this same
> directory. New chokepoints should be committed as YAML entries under
> `chokepoints/<tactic>/`. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full process.

**Last Updated:** YYYY-MM-DD
**Contributors:** [Your name/handle]

## Scope

**Tactics:** [MITRE Tactic(s)]
**Techniques:** [MITRE Technique ID(s)]
**Scope:** [Single technique / Multi-tactic]

Brief description of what this chokepoint covers.

## Variations

Current and historical methods that use this chokepoint:

| Method/Tool | First Seen | Status | Notes |
|-------------|------------|--------|-------|
| [Tool name] | YYYY-MM | Active | Current threat |
| [Tool name] | YYYY-MM | Declining | Less common now |
| [Tool name] | YYYY-MM | Legacy | Rarely seen |

## Prerequisites (The Chokepoint)

What **must** be true for this technique to work:

- [ ] Prerequisite 1
- [ ] Prerequisite 2
- [ ] Prerequisite 3

**Critical Conditions:**
- [Condition that cannot be bypassed]
- [Condition that cannot be bypassed]

## Evolution Timeline

### YYYY-MM — [Event Title]
- **Event:** [New tool/variant emerged]
- **Change:** [What changed vs. what stayed the same]
- **Detection Impact:** [How this affects detection]
- **The Constant:** [What did NOT change — the chokepoint]

### YYYY-MM — [Previous Iteration]
- **Event:** [Previous event]
- **Change:** [What changed]
- **Detection Impact:** [Impact on detection]
- **The Constant:** [What stayed the same]

## Detection Strategy

### Research Level
**Goal:** Initial visibility and baseline understanding

**Log Sources:**
- [Log source 1]
- [Log source 2]

**Detection Logic:**
```
[Broad detection approach]
```

**Expected FP Rate:** High
**Use Case:** Research, threat landscape mapping

### Hunt Level
**Goal:** Reduce noise while maintaining coverage

**Log Sources:**
- [Refined log sources]

**Detection Logic:**
```
[More specific detection with context]
```

**Expected FP Rate:** Medium
**Use Case:** Proactive hunting, campaign detection

### Analyst Level
**Goal:** Production SOC deployment

**Log Sources:**
- [Production log sources]

**Detection Logic:**
```
[High-fidelity detection with correlation]
```

**Expected FP Rate:** Low
**Use Case:** Automated alerting, IR escalation

## Sigma Rules

- [Research Level Rule](../sigma-rules/[technique]/research.yml)
- [Hunt Level Rule](../sigma-rules/[technique]/hunt.yml)
- [Analyst Level Rule](../sigma-rules/[technique]/analyst.yml)

## OSINT Sources

- [URLScan queries for this technique]
- [Shodan/Censys dorks]
- [Threat intel feeds]

## Known Bypasses

| Bypass Method | Mitigation | Detection |
|---------------|------------|-----------|
| [How attackers evade] | [How to prevent] | [How to detect anyway] |

## References

- [MITRE ATT&CK](https://attack.mitre.org/techniques/[ID])
- [Research paper/blog]
- [Tool documentation]
- [Threat intel report]

## Related Chokepoints

- [Another chokepoint that often occurs before/after this one]
- [Complementary detection opportunity]

---

**Detection Priority:** [CRITICAL/HIGH/MEDIUM/LOW]
**Threat Prevalence:** [VERY HIGH/HIGH/MEDIUM/LOW/EMERGING]
**Detection Difficulty:** [LOW/MEDIUM/HIGH]
