# Promotion checklist: graph-api-recon-burst

## Before merging to chokepoints/discovery/graph-api-recon-burst.yml

- [ ] All `<UNKNOWN>` fields resolved against lab data or cited source
- [ ] `WhyCantBypass` for each stage reviewed by a second analyst
- [ ] Sigma rules validated against real log samples (add to `RawLogs`)
- [ ] At least one variation has `ChokepointMapping` filled
- [ ] `EvolutionTimeline` has at least one entry
- [ ] Schema validation passes: `py scripts/validate_schema.py graph-api-recon-burst.yml`
- [ ] cp-reviewer BLOCK findings resolved
- [ ] UUID freshly generated (not copied from template)

## Key open items

- `hunt.yml` / `analyst.yml`: Both rules require category-count aggregation that cannot be expressed in standard Sigma. ES|QL or KQL implementation is mandatory before deployment. The Sigma stubs document the detection logic but are not directly executable — add KQL implementation to `Detections[Hunt].Logic` and note in promotion PR.
- `hunt.yml` `filter_known_tooling` placeholder: Must be replaced with known compliance/admin tool app IDs (e.g., Varonis, AvePoint, Stealthbits service principal IDs for the tenant). These tools commonly query multiple categories in one automated scan.
- `analyst.yml`: Correlation condition requires KQL multi-table join. The `<UNKNOWN>` stub must be replaced with a working KQL query joining MicrosoftGraphActivityLogs + SigninLogs on UPN within 1200s time window.
- Graph Activity Logs prerequisite: Confirm logs are enabled and ingested in the target tenant before relying on this detection. Add tenant configuration check to promotion gating.
- `c_sid` warning: Retain the documented mistake (`c_sid != user_object_id`) in the final chokepoint description and Sigma rule comments — this is a common analyst error that invalidates hunts.
- `/beta/ API disproportionate` signal: Not currently captured in Sigma stubs. Add `RequestUri|contains: '/beta/'` as a secondary enrichment field to the hunt rule.
- `RawLogs`: No sample Graph Activity Log entries attached.
- `OsintSources`: Confirmed as N/A — Graph recon bursts are internal Microsoft signals with no external OSINT observability.

## Source

Elastic Security Labs — Tycoon 2FA AiTM Detection Engineering (2026-05-27)
Primary intel: https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering
