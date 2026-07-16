# Changelog

All notable changes to this detection chokepoints repository will be documented in this file.

## [2026-07-16] - Edge-exploits backfill (May 20 - Jun 9) + refresh to Jul 16

Source: Defused Cyber honeypot telemetry, two manual console exports. A May 20 - Jun 9 export (`export_shared_20260609_000000.csv`, 46,209 rows) fills the gap the 2026-07-03 refresh left open, and a Jul 16 export (`export_shared_20260716_214508.csv`) extends coverage to Jul 16.

### Changed

- `_data/edge_exploits.yml` — total events 75,420 -> 88,299. Filled the May 20 - Jun 9 gap. CitrixBleed 2 (CVE-2025-5777) 56,338 -> 62,205 hits, now 70% of all traffic; a late-May surge is the largest day on record: May 26 alone is 29,520 hits, 29,274 of them CitrixBleed 2 from a single source (`193.202.84.145`). Live window extended to Jul 16. Next.js RCE (CVE-2025-55182) 7,146 and cPanel WHM (CVE-2026-41940) 2,049.
- `trends/edge-exploits/index.html` — refreshed the volume callout, target-distribution intro, and the CitrixBleed 2 / Next.js / cPanel sections to the new totals and the May 26 single-source surge; extended the CitrixBleed 2 daily chart through Jul 16 (it stopped at the Apr 13 baseline before). Removed the now-dormant `partial`-day chart styling, superseded by the gap treatment below.
- `scripts/transform_defused_csv.py` — four changes: (1) day merge is now per-day MAX-wins instead of newest-wins, so a newer export's partial window-start day can no longer overwrite an older export's complete count (fixed a Jun 16 undercount, 10 vs the true 139); (2) a row-capped export's truncated oldest day now renders as a GAP rather than a flagged partial bar (supersedes the 2026-07-03 partial approach; Jun 10 is the first such gap), fillable later by a narrow uncapped export that wins the max; (3) strips the source `:port` that newer exports append to the Attacker IP field, so unique-IP counts stay consistent across the two export formats; (4) the CitrixBleed 2 daily series now includes the live window, not just the frozen baseline.
- `_data/edge_exploits_provenance.yml` — regenerated to the Apr - Jul 2026 window (was Jul 3), 2,998 cumulative unique source IPs. The local (gitignored) `enrich_asns.py` got the same per-day MAX-wins merge + Jun 10 gap + `:port` strip: it had been raw-summing overlapping exports, inflating June 6.6x (105,888 vs the correct 16,113) and floating one ASN (datacampus, the truncated Jun 10 spike's host) into the top purely as a double-counting artifact. Deduped per-month ASN totals now match the event page exactly (May 50,016 / Jun 16,113 / Jul 3,537).
- `scripts/transform_provenance.py` — `short()` now falls back to the AS handle when the org description would overflow the label, instead of a mid-word cut (top provider reads `GreatFlower`, not `Emil Vitukhnovskii trading a`). Other labels unchanged.

### Notes

- Jun 10, 2026: both the Jul 3 and Jul 10 exports hit the 50,000-row cap and truncate Jun 10 (at least 36,528 hits, true count unknown). Rendered as a gap rather than published as a truncated floor. A narrow Jun 10 re-export would close it automatically.
- The May 20 - Jun 9 gap noted in the 2026-07-03 entry is now filled with a complete (uncapped) export.
- Provenance enrichment (`enrich_asns.py`, `hll.py`, `bulletproof_asns.yml`) is gitignored / local-only (it touches raw IPs + an optional key, decision #009), so its merge fix lives on the operator's machine, not in the repo; only the IP-free `_data/edge_exploits_provenance.yml` aggregate is committed. Team Cymru keyless resolution only; the IPinfo cross-check was skipped.
- Verified: transform output cross-checked against an independent MAX-wins re-derivation (live total 73,298, CitrixBleed 2 54,093 live, Citrix decoy 54,625 live, combined 88,299, unique IPs 2,988 all matched); provenance per-month totals reconciled to the event page (May/Jun/Jul exact); page built clean under Jekyll and all charts screenshot-verified (May 26 tower, Jun 10 gap, provenance stacked chart with May dominant).

## [2026-07-03] - Edge-exploits trend refresh (Jun 10 - Jul 3, 2026 export)

Source: Defused Cyber honeypot telemetry, manual console export (`export_shared_20260703_183931.csv`)

### Changed

- `_data/edge_exploits.yml`, `_data/edge_exploits_provenance.yml` — merged the new export; total events 25,420 → 75,420. CitrixBleed 2 (CVE-2025-5777) exploitation jumped 11,145 → 56,338 hits, Citrix NetScaler now >90% of decoy traffic.
- `trends/edge-exploits/index.html` — chart caption and volume blurb now pull `meta.date_range_note` / `meta.live_decoy_count` via Liquid instead of hardcoded text, so they stay in sync on future refreshes. Daily chart flags row-cap-truncated days (new `partial` styling, distinct from the existing export-cutoff `artifact` styling).
- `scripts/transform_defused_csv.py` — generalized gap detection (previously hardcoded to the one-time Apr 14-18 baseline seam) to scan the full live window every run, and added detection for row-capped exports (Defused's console appears to cap at 50,000 rows; `unverified:` no documented limit found, inferred from this export's clean mid-record cutoff).

### Notes

- Confirmed gap: May 20 - Jun 9, 2026 (21 days) — no export was taken, no data recoverable.
- Confirmed partial day: Jun 10, 2026 — the new export hit the suspected 50,000-row cap sorted newest-first, cutting off before covering the full day. Flagged on the page rather than excluded or silently trusted.
- `--check-seed` regression-tested clean against the original May-only seed before merging the new export.

## [2026-05-29] - AiTM / Tycoon 2FA Chokepoints (4 new entries)

Source: Elastic Security Labs — Tycoon 2FA AiTM Detection Engineering (2026-05-27)
https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering

### Added

- `chokepoints/credential-access/aitm-websocket-relay.yml` — AiTM WebSocket Kit Relay (T1539, T1078.004): Node.js UA on Entra ID sign-in + cloud-VPS/residential two-tier ASN pattern. CRITICAL priority. 2 chokepoint stages, 2 kit variants (Tycoon 2FA, EvilProxy).
- `sigma-rules/aitm-websocket-relay/research.yml` — Baseline Node.js UA on any Entra sign-in
- `sigma-rules/aitm-websocket-relay/hunt.yml` — Node.js UA on high-value M365 apps
- `sigma-rules/aitm-websocket-relay/analyst.yml` — Two-tier ASN correlation stub (KQL required for full correlation)

- `chokepoints/defense-evasion/oauth-device-code-phishing.yml` — OAuth Device Code Phishing via Auth Broker (T1550.001): MAB app ID 29d9ed98-... + deviceCode protocol + isInteractive = high-confidence phishing. HIGH priority. CA policy prevention documented.
- `sigma-rules/oauth-device-code-phishing/research.yml` — All device-code sign-ins baseline
- `sigma-rules/oauth-device-code-phishing/hunt.yml` — Device-code on MAB app ID
- `sigma-rules/oauth-device-code-phishing/analyst.yml` — MAB + deviceCode + isInteractive triple

- `chokepoints/discovery/graph-api-recon-burst.yml` — Post-AiTM Graph API Reconnaissance Burst (T1087.004, T1069.003, T1526): 4+ endpoint categories in 60s = automated operator console, not human navigation. HIGH priority. Requires Graph Activity Logs. c_sid pivot mistake documented.
- `sigma-rules/graph-api-recon-burst/research.yml` — Any recon endpoint in Graph Activity Logs
- `sigma-rules/graph-api-recon-burst/hunt.yml` — Empty DeviceId + recon endpoint stub; KQL category-tagging aggregation documented inline
- `sigma-rules/graph-api-recon-burst/analyst.yml` — Graph burst + preceding AiTM sign-in correlation; KQL join documented inline

- `chokepoints/persistence/aitm-device-prt-enrollment.yml` — AiTM Kit Device PRT Enrollment (T1098.005): axios UA on DRS EnrollmentServer/device call = synthetic device PRT that survives revokeSignInSessions. HIGH priority. IR playbook fix documented (delete devices BEFORE revoking sessions).
- `sigma-rules/aitm-device-prt-enrollment/research.yml` — All device registration events baseline
- `sigma-rules/aitm-device-prt-enrollment/hunt.yml` — Non-native UA on device registration
- `sigma-rules/aitm-device-prt-enrollment/analyst.yml` — Non-native UA correlated with preceding AiTM sign-in; KQL join documented inline

### Pending lab validation (noted inline in each file)

- `RawLogs` sample entries not yet attached — requires live M365 tenant
- `filter_legit_automation` / `filter_known_legitimate` placeholders in hunt/analyst Sigma rules need tenant-specific service account UPNs
- `graph-api-recon-burst`: KQL/ES|QL required for production (category-count aggregation unsupported in standard Sigma)
- `aitm-device-prt-enrollment`: AuditLogs field name for UserAgent requires lab verification
- `aitm-websocket-relay` analyst.yml: ASN enrichment lookup table required

## [2026-03-30] - LSASS Credential Dumping Chokepoint

### Added
- `chokepoints/credential-access/lsass-credential-dumping.yml` - New chokepoint: LSASS credential dumping (T1003.001)
- `sigma-rules/lsass-credential-dumping/research.yml` - Research-level Sigma rule (baseline all non-system LSASS access via process_access)
- `sigma-rules/lsass-credential-dumping/hunt.yml` - Hunt-level Sigma rule (CallTrace + source path behavioral filtering)
- `sigma-rules/lsass-credential-dumping/analyst.yml` - Analyst-level Sigma rule (triple-AND: access mask + dump mechanism + non-standard source)
- `emulation/lsass-credential-dumping/emulate.ps1` - PowerShell emulation script with SeDebugPrivilege handling and PPL detection
- 24 tool variations tracked (Mimikatz, comsvcs.dll, nanodump, HandleKatz, Cobalt Strike, Sliver, Havoc, Brute Ratel, Mythic, and more)
- 4 raw log samples (EID 10 classic, EID 10 direct syscall, EID 10 handle duplication, EID 1 comsvcs LOLBin)
- 6 OSINT pivot queries (VirusTotal, GitHub, LOLDrivers, ANY.RUN)

## [2025-02-28] - LOLBAS-Style Restructuring

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
