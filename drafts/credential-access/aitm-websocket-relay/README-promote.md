# Promotion checklist: aitm-websocket-relay

## Before merging to chokepoints/credential-access/aitm-websocket-relay.yml

- [ ] All `<UNKNOWN>` fields resolved against lab data or cited source
- [ ] `WhyCantBypass` for each stage reviewed by a second analyst
- [ ] Sigma rules validated against real log samples (add to `RawLogs`)
- [ ] At least one variation has `ChokepointMapping` filled
- [ ] `EvolutionTimeline` has at least one entry
- [ ] Schema validation passes: `py scripts/validate_schema.py aitm-websocket-relay.yml`
- [ ] cp-reviewer BLOCK findings resolved
- [ ] UUID freshly generated (not copied from template)

## Key open items

- `analyst.yml`: Two-tier ASN correlation requires SIEM enrichment with cloud-provider ASN list. Implement as KQL join or dedicated ASN lookup table before promoting. Mark `<UNKNOWN>` fields resolved once ASN lookup is confirmed.
- `hunt.yml`: `filter_legit_automation` placeholder (`<UNKNOWN>`) must be replaced with actual tenant service account UPNs before deployment.
- EvilProxy variation: `AppDisplayName` field in `ChokepointMapping` is listed as `<UNKNOWN>` — verify against lab data or EvilProxy-specific reporting.
- `RawLogs`: No sample sign-in log entries attached. Add before analyst-tier promotion.

## Source

Elastic Security Labs — Tycoon 2FA AiTM Detection Engineering (2026-05-27)
Primary intel: https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering
