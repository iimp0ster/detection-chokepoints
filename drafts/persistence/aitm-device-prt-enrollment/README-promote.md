# Promotion checklist: aitm-device-prt-enrollment

## Before merging to chokepoints/persistence/aitm-device-prt-enrollment.yml

- [ ] All `<UNKNOWN>` fields resolved against lab data or cited source
- [ ] `WhyCantBypass` for each stage reviewed by a second analyst
- [ ] Sigma rules validated against real log samples (add to `RawLogs`)
- [ ] At least one variation has `ChokepointMapping` filled
- [ ] `EvolutionTimeline` has at least one entry
- [ ] Schema validation passes: `py scripts/validate_schema.py aitm-device-prt-enrollment.yml`
- [ ] cp-reviewer BLOCK findings resolved
- [ ] UUID freshly generated (not copied from template)

## Key open items

- `hunt.yml` / `analyst.yml`: Field name `UserAgent` in AuditLogs must be verified — the actual field may be `InitiatedBy.app.displayName`, `AdditionalDetails`, or a nested property. Verify against lab data before deployment.
- `analyst.yml`: Correlation condition requires KQL/SIEM join implementation. The `<UNKNOWN>` stub must be replaced with a working multi-table query.
- `filter_known_automation` placeholder in `hunt.yml` must be populated with documented MDM/Intune service principal IDs for the tenant.
- `PRT Persistence Post-Revocation` stage: Verify which log source captures PRT issuance post-enrollment — may require Graph Activity Logs (`incomingTokenType: primaryRefreshToken`) not captured in AuditLogs.
- IR note in description ("delete devices BEFORE revoking sessions") verified from Elastic source — retain in final chokepoint description.
- `RawLogs`: No sample AuditLogs device registration entries attached.

## Source

Elastic Security Labs — Tycoon 2FA AiTM Detection Engineering (2026-05-27)
Primary intel: https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering
