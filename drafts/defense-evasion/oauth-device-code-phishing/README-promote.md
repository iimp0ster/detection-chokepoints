# Promotion checklist: oauth-device-code-phishing

## Before merging to chokepoints/defense-evasion/oauth-device-code-phishing.yml

- [ ] All `<UNKNOWN>` fields resolved against lab data or cited source
- [ ] `WhyCantBypass` for each stage reviewed by a second analyst
- [ ] Sigma rules validated against real log samples (add to `RawLogs`)
- [ ] At least one variation has `ChokepointMapping` filled
- [ ] `EvolutionTimeline` has at least one entry
- [ ] Schema validation passes: `py scripts/validate_schema.py oauth-device-code-phishing.yml`
- [ ] cp-reviewer BLOCK findings resolved
- [ ] UUID freshly generated (not copied from template)

## Key open items

- `hunt.yml` / `analyst.yml`: `filter_known_legitimate` placeholders must be replaced with tenant-specific documented MAB device-code sources before deployment. Most managed tenants have zero legitimate interactive MAB device-code flows — verify before adding any filter.
- `Token Inheritance via FOCI` stage (hunt-tier): `SigmaRef` points to `sigma/hunt.yml` which covers device-code redemption, not FOCI token exchange. A separate Sigma stub targeting `NonInteractiveUserSignInLogs` for FOCI exchange signals would strengthen this stage. Add as a second hunt-tier rule before promotion.
- `research.yml` field `AuthenticationProtocol` — verify exact Sigma field name against SigmaHQ Azure log source definitions (`authenticationProtocol` vs `AuthenticationProtocol`). Case sensitivity matters for some backends.
- `IsInteractive` field in `analyst.yml` — verify Sigma field name casing against log source.
- `RawLogs`: No sample interactive device-code sign-in log entries attached.
- CA policy prevention (error 53003): Document tenant CA policy status before deploying hunt/analyst rules — if CA policy is in place, research rule will show zero results (expected).

## Source

Elastic Security Labs — Tycoon 2FA AiTM Detection Engineering (2026-05-27)
Primary intel: https://www.elastic.co/security-labs/tycoon-2fa-aitm-detection-engineering
