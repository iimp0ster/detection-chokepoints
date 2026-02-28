# Changelog

All notable changes to this detection chokepoints repository will be documented in this file.

## [2025-02-28] — LOLBAS-Style Restructuring

### Added
- `CONTRIBUTING.md` — full contribution guide (schema requirements, PR checklist, what not to submit)
- `schema/chokepoint-schema.yml` — canonical field definitions and valid values for all YAML entries
- `chokepoints/initial-access/clickfix-techniques.yml` — ClickFix converted to structured YAML
- `chokepoints/initial-access/renamed-rmm-tools.yml` — Renamed RMM tools converted to structured YAML
- `chokepoints/lateral-movement/remote-execution-tools.yml` — Remote execution tools (HackTools) converted to YAML
- `chokepoints/defense-evasion/ransomware-service-manipulation.yml` — Ransomware service manipulation converted to YAML
- `sigma-rules/clickfix/research.yml` — Research-level Sigma rule for ClickFix chokepoint
- `sigma-rules/clickfix/hunt.yml` — Hunt-level Sigma rule for ClickFix chokepoint
- `sigma-rules/clickfix/analyst.yml` — Analyst-level Sigma rule for ClickFix chokepoint
- `sigma-rules/renamed-rmm/research.yml` — Research-level Sigma rule for Renamed RMM tools
- `sigma-rules/renamed-rmm/hunt.yml` — Hunt-level Sigma rule for Renamed RMM tools
- `sigma-rules/renamed-rmm/analyst.yml` — Analyst-level Sigma rule for Renamed RMM tools
- `sigma-rules/remote-execution/research.yml` — Research-level Sigma rule for Remote Execution tools
- `sigma-rules/remote-execution/hunt.yml` — Hunt-level Sigma rule for Remote Execution tools
- `sigma-rules/remote-execution/analyst.yml` — Analyst-level Sigma rule (KQL correlation included)
- `sigma-rules/ransomware-service/research.yml` — Research-level Sigma rule for ransomware service stops
- `sigma-rules/ransomware-service/hunt.yml` — Hunt-level Sigma rule for service stop/delete combination
- `sigma-rules/ransomware-service/analyst.yml` — Analyst-level Sigma rule (Sophos + KQL threshold query)
- `intel/clickgrab.md` — ClickGrab documentation: what it is, how to use it for threat hunting
- `attack-chains/ransomware.md` — Ransomware kill chain with chokepoint references (updated links)
- `attack-chains/infostealers.md` — Infostealer IAB pipeline with source attribution
- `trends/2025-q1.md` — Q1 2025 threat trends with source citations and chokepoint links
- `trends/chokepoint-shifts.md` — True shift vs. tool rotation analysis
- `templates/chokepoint-template.yml` — Canonical YAML template for new submissions
- `templates/chokepoint-template.md` — Human-readable markdown template
- `templates/quick-add.md` — Fast template for adding new tool variants
- `templates/evolution-tracker.md` — Template for tracking chokepoint evolution over time
- `templates/EXAMPLE-WORKFLOW.md` — Complete workflow example: adding Impacket RDP shadowing

### Changed
- `README.md` — Full rewrite: military chokepoint hook (Thermopylae, Fulda Gap), thesis statement
  ("TTPs evolve. Chokepoints don't."), chokepoint index table, updated repo structure diagram,
  How to Use section by persona (Hunter / Detection Engineer / Evolution Tracker)
- All chokepoint entries now structured as YAML with standardized schema instead of freeform markdown
- Source citations added to infostealers.md (HudsonRock, RedCanary, Cyberint)
- trends/2025-q1.md now includes links to ClickGrab intel resource

### Removed
- `clickfix-techniques.md` — superseded by `chokepoints/initial-access/clickfix-techniques.yml`
- `renamed-rmm-tools.md` — superseded by `chokepoints/initial-access/renamed-rmm-tools.yml`
- `remote-execution-tools.md` — superseded by `chokepoints/lateral-movement/remote-execution-tools.yml`
- `ransomware-service-manipulation.md` — superseded by `chokepoints/defense-evasion/ransomware-service-manipulation.yml`
- `ransomware.md` — moved to `attack-chains/ransomware.md`
- `infostealers.md` — moved to `attack-chains/infostealers.md`
- `2025-trends.md` — moved to `trends/2025-q1.md`
- `chokepoint-shifts.md` — moved to `trends/chokepoint-shifts.md`
- `chokepoint-template.md` — moved to `templates/chokepoint-template.md`
- `quick-add.md` — moved to `templates/quick-add.md`
- `evolution-tracker.md` — moved to `templates/evolution-tracker.md`
- `EXAMPLE-WORKFLOW.md` — moved to `templates/EXAMPLE-WORKFLOW.md`

## [Unreleased]

## [2025-01-15] - Repository Creation

### Added
- Initial commit
- Repository structure established
- Core documentation framework

---

## Update Format

When adding new content, use this format:

```markdown
## [YYYY-MM-DD] - Brief Description

### Added
- New chokepoint: [Name] ([MITRE Technique])
- New attack chain: [Name]
- New sigma rule: [Name]

### Updated
- Chokepoint [Name]: Added [Tool/Variant] variation
- Threat evolution: Q[X] YYYY trends
- Sigma rule [Name]: Improved detection logic

### Changed
- Reorganized [Directory/Section]
- Updated [File] to reflect new TTPs

### Deprecated
- [Item that is being phased out]

### Removed
- [Item that has been removed]
```

---

## Contribution Guidelines

When updating the repository:

1. **New Threat Variant**: Use `templates/quick-add.md`, update relevant chokepoint
2. **New Chokepoint**: Use `templates/chokepoint-template.md`, create full documentation
3. **Sigma Rule Update**: Version the rule, maintain old version for reference
4. **Trend Analysis**: Update quarterly in `threat-evolution/[year]-trends.md`
5. **Always**: Log change in this CHANGELOG with date and description
