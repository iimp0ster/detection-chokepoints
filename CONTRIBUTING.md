# Contributing to Detection Chokepoints

Thank you for contributing to this community detection engineering resource.
This guide explains how to submit new chokepoints, add variations to existing entries,
improve sigma rules, and keep the repository organized.

---

## Core Principle

Contributions must be grounded in **chokepoints** — the prerequisites that attackers
*cannot bypass* regardless of tool choice. We are not building an IOC feed or a
signature database. We are documenting invariant conditions and building durable
detections around them.

**Ask yourself before submitting:**
> "If the attacker switches tools tomorrow, does this detection still fire?"

If yes, it's a chokepoint. If no, it may be a useful IOC, but it's not a chokepoint entry.

---

## Types of Contributions

### 1. New Chokepoint Entry
A new technique or attack requirement not yet documented in the repo.

**Requirements:**
- Complete YAML entry (all required fields per `schema/chokepoint-schema.yml`)
- `AttackerControls` and `AttackerCannotControl` lists filled in — these must be written before chokepoint stages
- At least Research and Hunt level Sigma rules, **or** a documented
  `NoStandaloneSigmaRationale` where the use case is inherently a multi-source,
  time-bounded correlation (for example passive infrastructure inventory plus an
  independent endpoint-to-service relationship). The rationale must explain why
  a single event would weaken the stated attribution and false-positive
  boundaries, and must include a reproducible validation contract.
- Analyst level sigma rule (or documented rationale for why one isn't feasible)
- At least one source reference (MITRE, research blog, threat report)

### 2. New Variation on Existing Chokepoint
A new tool, family, or method that exploits an existing chokepoint.

**Requirements:**
- Update the `Variations:` list in the relevant YAML file with all required variation fields (see [Variation Fields](#variation-fields) below)
- Add an `EvolutionTimeline:` entry with `DetectionImpact` explaining whether existing detections still cover the new variant
- Update `CHANGELOG.md`

### 3. Improved Sigma Rule
Better detection logic, reduced false positives, or a new maturity level.

**Requirements:**
- Maintain the existing rule at its current version as a comment or separate file
  if the logic change is substantial
- Document what changed and why in a comment block at the top of the rule
- Test against known-good and known-bad scenarios before submitting

### 4. IOK Lure Detection Rule
Sigma-based rules for phishing/lure page detection via web proxy or phish.report.

**Requirements:**
- Rule file at `iok-rules/<chokepoint>/<name>.yml`
- Uses `html`, `js`, `dom`, `requests`, and/or `headers` matchers
- See `iok-rules/clickfix/clickfix-lure.yml` as reference
- Link from the relevant chokepoint YAML under `EarlyDetections:`

### 5. Emulation Script
PowerShell/bash scripts that simulate chokepoint behavior in a controlled lab.

**Requirements:**
- Script at `emulation/<chokepoint>/emulate.ps1` (or `.sh`)
- Must include `SafetyNotes` — lab use only, isolated VM only
- Map to an Atomic Red Team technique ID via `AtomicRef`
- Outbound connections must point to benign destinations (e.g., `example.com`)

### 6. Intel Resource
A free, community-accessible resource that helps hunt a specific chokepoint.

**Requirements:**
- Link from the relevant chokepoint YAML under `Intel:`
- Create a doc under `intel/` explaining how to use the resource
- Must be freely accessible (no paywalled intel feeds)

---

## Chokepoint YAML Schema

All chokepoint entries live at `chokepoints/<tactic>/<technique-name>.yml`.

**Valid tactic directory names:**
```
initial-access/
execution/
persistence/
privilege-escalation/
defense-evasion/
credential-access/
discovery/
lateral-movement/
collection/
command-and-control/
exfiltration/
impact/
```

**Required fields** (see `schema/chokepoint-schema.yml` for full definitions):

| Field | Type | Example |
|-------|------|---------|
| `Name` | string | `"ClickFix Techniques"` |
| `Id` | UUIDv4 | `"c7f2a1b4-3e8d-4a9c-8b5f-2d1e6f0a7c3b"` |
| `MitreIds` | list | `["T1204.001", "T1204.004"]` |
| `Tactics` | list | `["Initial Access"]` |
| `Techniques` | list | `["User Execution: Malicious Copy and Paste"]` |
| `DetectionPriority` | enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `ThreatPrevalence` | enum | `VERY HIGH`, `HIGH`, `MEDIUM`, `LOW`, `EMERGING` |
| `DetectionDifficulty` | enum | `LOW`, `MEDIUM`, `HIGH` |
| `Description` | string | 2-4 sentences |
| `LastUpdated` | date | `"2026-03-10"` |
| `Author` | string | `"@your-handle"` |

**Generating a UUIDv4 for the `Id` field:**
```bash
python3 -c "import uuid; print(uuid.uuid4())"
```

Use the YAML template at `templates/chokepoint-template.yml` as a starting point.

### Framework Fields (required for new entries)

These must be filled **before** writing chokepoint stages. If you can't list at least
one item the attacker cannot control, this may not be a chokepoint.

| Field | Purpose |
|-------|---------|
| `Prerequisites` | Conditions that must be true for the attack to succeed |
| `AttackerControls` | List of things the attacker can change (variables — lures, encoding, infra) |
| `AttackerCannotControl` | List of invariant prerequisites (the chokepoints — the things your detections target) |

See `FRAMEWORK.md` for the full methodology.

### Chokepoint Stage Fields

Each stage in `Chokepoints:` requires:

| Field | Purpose |
|-------|---------|
| `Stage` | Observable behavior name (e.g., "Clipboard Seeding") — not a kill chain phase |
| `Input` | What state exists before this stage fires |
| `Invariant` | What MUST the attacker do at this stage, regardless of variant |
| `Observable` | Specific telemetry artifact (event IDs, field values) |
| `WhyCantBypass` | Why the attacker cannot skip this step — the most important sentence in the stage |
| `LogSources` | Log sources that cover this stage |
| `DetectionTier` | Research, Hunt, or Analyst |
| `SigmaRef` | Relative path to the Sigma/IOK rule |

Optional but recommended:

| Field | Purpose |
|-------|---------|
| `BypassNote` | Known evasion paths — renders as a red callout |
| `TruePositive` | Real log example with `Title`, `Log`, `KeySignal` |

### Variation Fields

Each entry in `Variations:` supports different fields depending on the technique type.

**Required for all variations:**

| Field | Purpose |
|-------|---------|
| `Name` | Tool or method name |
| `FirstSeen` | Quarter or date (e.g., `"2024-Q1"`) |
| `Status` | `Active`, `Emerging`, `Declining`, `Legacy`, `Disrupted` |
| `SourceURL` | Full URL to the original report. Use a YAML list for multiple sources |
| `NotesShort` | One-line summary for card header |
| `Notes` | 2-3 sentences on what makes this variant different |
| `VariantId` | URL-safe slug (e.g., `"clickfix-original"`) |
| `ChokepointMapping` | Maps variant back to chokepoint stages (e.g., `"clipboard write → powershell.exe (parent: explorer.exe) → outbound HTTP"`) |

**For initial access / social engineering techniques** (ClickFix, Renamed RMM):

| Field | Purpose |
|-------|---------|
| `Lure` | What the user sees — visual elements, social engineering narrative, interaction flow |
| `LureTags` | List of identifying elements (e.g., `"Cloudflare impersonation"`, `"Win+R instruction"`) |
| `LurePreview` | Path to HTML lure recreation (e.g., `/assets/lures/clickfix-original.html`) |
| `Payloads` | List of per-platform payloads with `Platform`, `Command` (defanged), and `Note` |

**For post-compromise techniques** (EDR Bypass, Ransomware, Remote Execution):

| Field | Purpose |
|-------|---------|
| `Command.Invocation` | The actual CLI command or tool invocation (defanged) |
| `Command.Context` | When/how this command is typically executed |
| `Command.Artifacts` | List of observable artifacts (e.g., `"Sysmon EID 1: sc.exe with 'stop'"`) |

**Important rules for variations:**
1. Defang all IOCs: `hxxps[://]`, `[.]com`, etc.
2. Payload examples must be sourced from the `SourceURL` article — not fabricated
3. If `SourceURL` has multiple links, use a YAML list — they render as separate hyperlinks
4. If a field is empty or absent, the template will not render that section

---

## Sigma Rule Requirements

Sigma rules live at `sigma-rules/<technique-name>/<level>.yml` where level is
`research`, `hunt`, or `analyst`.

**Each rule must include:**
- `title` — descriptive, specific to what it catches
- `id` — UUIDv4 (different from the chokepoint entry ID)
- `status` — `experimental` for new submissions
- `description` — what the rule detects and why it fires at this level
- `references` — at minimum the MITRE technique URL and one blog/report
- `author` — your handle
- `date` — submission date in `YYYY/MM/DD` format
- `tags` — MITRE ATT&CK tags (`attack.<tactic>`, `attack.t<id>`) + `detection.maturity.<level>`
- `logsource` — must use standard Sigma logsource categories
- `detection` — valid Sigma detection block
- `falsepositives` — list realistic FP scenarios
- `level` — `informational` (research), `low`/`medium` (hunt), `high`/`critical` (analyst)

**Sigma level guidance:**

| Maturity | Sigma level | Notes |
|----------|-------------|-------|
| Research | `informational` | High FP expected; for baselining only |
| Hunt | `low` or `medium` | Reduced FPs; for active hunting |
| Analyst | `high` or `critical` | Minimal FPs; SOC-deployable |

**Common logsource categories:**
```yaml
# Process creation (Sysmon EID 1 or Security EID 4688)
logsource:
  category: process_creation
  product: windows

# Network connection (Sysmon EID 3)
logsource:
  category: network_connection
  product: windows

# File events (Sysmon EID 11)
logsource:
  category: file_event
  product: windows

# Windows event log (System, Security, etc.)
logsource:
  product: windows
  service: system   # or: security, application, sysmon
```

---

## PR Process

1. **Fork** the repository
2. **Create a branch** named `<your-handle>/<chokepoint-name>` (e.g., `jsmith/browser-cred-theft`)
3. **Copy** `templates/chokepoint-template.yml` to `chokepoints/<tactic>/<name>.yml`
4. **Fill in** `AttackerControls` and `AttackerCannotControl` first — then write stages
5. **Create** sigma rules in `sigma-rules/<name>/research.yml`, `hunt.yml`, `analyst.yml`
6. **Update** `CHANGELOG.md` with your entry
7. **Submit** a PR with the checklist below completed

**PR Description Checklist:**

```markdown
## Chokepoint Submission

- [ ] YAML entry at `chokepoints/<tactic>/<name>.yml` with all required fields
- [ ] Unique UUIDv4 generated for `Id` field
- [ ] All MITRE IDs verified against current ATT&CK framework
- [ ] `AttackerControls` and `AttackerCannotControl` lists filled in
- [ ] Chokepoint stages include `Input`, `Invariant`, `Observable`, `WhyCantBypass`
- [ ] Research sigma rule at `sigma-rules/<name>/research.yml`
- [ ] Hunt sigma rule at `sigma-rules/<name>/hunt.yml`
- [ ] Analyst sigma rule at `sigma-rules/<name>/analyst.yml`
  - If not provided: [ ] Documented why analyst-level rule is not feasible
- [ ] At least one source reference included
- [ ] Variation payload examples sourced from cited articles (not fabricated)
- [ ] All IOCs defanged (hxxps[://], [.]com)
- [ ] CHANGELOG.md updated
- [ ] Related chokepoints cross-referenced via `RelatedChokepoints:` field

## What is the chokepoint?

[One sentence describing the invariant prerequisite]

## Why can't attackers bypass this condition?

[Brief explanation of why this requirement cannot be avoided]

## Test environment / validation

[How did you validate this detection? What logs/telemetry did you use?]
```

---

## What Not to Submit

| Don't submit | Why |
|-------------|-----|
| Raw IP/domain/hash lists | These are IOCs, not chokepoints; they belong in threat intel feeds |
| Detection for a single tool by name | Too narrow; reframe around the chokepoint the tool exploits |
| Vendor-specific content | Must be applicable across vendor products (tool-agnostic) |
| Rules without `falsepositives` field | Understanding FP scenarios is part of the entry quality bar |
| MITRE IDs not in the current ATT&CK framework | Verify at https://attack.mitre.org/ before submitting |
| Fabricated payload examples | Payload commands in variations must be sourced from the cited `SourceURL` |

---

## Code of Conduct

This repository is for **defensive** security content. Contributions must be usable
by defenders. Do not submit offensive tooling, payload generation code, or content
designed to evade detection rather than enable it.

---

## Questions?

Open a GitHub Issue with the `question` label. Tag relevant chokepoint files in the
issue body so maintainers can provide context-aware answers.
