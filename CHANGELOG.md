# Changelog

All notable changes to this detection chokepoints repository will be documented in this file.

## [Unreleased]

### Added
- Initial repository structure
- Framework documentation (README.md, FRAMEWORK.md)
- Templates for chokepoint documentation and quick-add entries
- Chokepoint examples:
  - ClickFix Techniques (Initial Access)
  - Renamed RMM Tools (Initial Access)
  - Remote Execution Tools (Lateral Movement)
  - Ransomware Service Manipulation (Defense Evasion)
- Attack chain examples:
  - Ransomware
  - Infostealers
- Threat evolution tracking:
  - 2025 Q1 trends
  - Chokepoint shifts analysis
- Sigma rules:
  - ClickFix detection (research, hunt, analyst levels)
  - Remote execution detection
  - Ransomware service stop detection

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
