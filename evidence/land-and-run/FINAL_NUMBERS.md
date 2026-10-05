# Final numbers (v2)

Every figure a write-up would cite. All figures except the Task B rows use the same scope:

- operator sessions excluded
- the SQLite snapshot as the source of truth
- window 2026-04-27T23:09:48Z to 2026-09-26T14:24:07Z (153 calendar days)

The Task B rows use the earlier report's own window, as stated in each row. Paths under Query are relative to the pack. Rerun everything with `queries/run_all.sh`.

## Scope and population

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| Window | 2026-04-27T23:09:48Z to 2026-09-26T14:24:07Z; 153 calendar days (151.63 elapsed) | n/a | C05 | `queries/01_sources_and_counts.py` |
| Sessions removed by the operator exclusion | 107 | of 141,293 sessions before exclusion | O01 | `queries/01_sources_and_counts.py` |
| Events removed by the operator exclusion | 739 (390 command) | of 887,233 events before exclusion | O01 | `queries/01_sources_and_counts.py` |
| Possible further operator sources (not excluded) | 6 | all non-operator sources | O02 | `queries/13_operator_lookalikes.py` |
| Sessions | 141,186 | n/a | C06 | `queries/01_sources_and_counts.py` |
| Distinct source IPs | 6,613 | n/a | C06 | `queries/01_sources_and_counts.py` |
| Sessions with commands | 69,979 (49.57%) | of 141,186 sessions | C06 | `queries/01_sources_and_counts.py` |
| Command events logged | 454,168 | n/a | C03 | `queries/01_sources_and_counts.py` |
| Whole-line echoes collapsed | 49,441 | of 454,168 command events | C03 | `queries/01_sources_and_counts.py` |
| Atomic commands after collapse | 404,727 | n/a | C03 | `queries/01_sources_and_counts.py` |

## Recon-then-fetch classes

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| Recon then fetch | 712 (1.02%) | 69,979 sessions with commands | C08 | `queries/02_classify_sessions.py` |
| Fetch with no recon | 130 (0.19%) | 69,979 | C08 | `queries/02_classify_sessions.py` |
| Fetch then recon | 0 (0.00%) | 69,979 | C08b | `queries/02_classify_sessions.py` |
| Recon only | 1,344 (1.92%) | 69,979 | C08 | `queries/02_classify_sessions.py` |
| Non-download delivery | 4,174 (5.96%) | 69,979 | C08, C16 | `queries/02_classify_sessions.py` |
| None of the above | 63,619 (90.91%) | 69,979 | C08 | `queries/02_classify_sessions.py` |
| Echo-ok probe sessions | 63,364 | of 63,619 none-of-the-above sessions | C09 | `queries/00b_line_shapes.py` |
| Fetching sessions that ran recon first | 712 (84.56%) | 842 sessions that attempted a download utility | C11 | `queries/02_classify_sessions.py` |
| Fetching sessions with no recon | 130 (15.44%) | 842 | C11 | `queries/02_classify_sessions.py` |
| Recon-then-fetch sources | 13 | n/a | C12 | `queries/09_class_sources.py` |
| Top-3 shapes' share of recon-then-fetch | 687 (96.49%), from 4 sources | 712 recon-then-fetch sessions | C12 | `queries/11_shape_sources.py` |
| Login to first recon (s), min / median / p90 / max | 0.09 / 0.31 / 0.43 / 19.62 | n = 712 | C13 | `queries/02_classify_sessions.py` |
| First recon to first fetch (s), min / median / p90 / max | 0.00 / 0.00 / 0.29 / 326.78 | n = 712 | C13 | `queries/02_classify_sessions.py` |
| Login to first fetch (s), min / median / p90 / max | 0.23 / 0.39 / 0.73 / 333.49 | n = 712 | C13 | `queries/02_classify_sessions.py` |
| Recon and fetch in one exec request | 689 | of 712 | C13 | `queries/02_classify_sessions.py` |
| Fetch within 300 s of first recon | 711 | of 712 | C13 | `queries/09_class_sources.py` |
| Distinct command sequences / transcripts | 16 / 18 | 712 | C14 | `queries/02_classify_sessions.py` |
| Exactly one recon command before fetch | 319 (44.80%) | 712 | C15 | `queries/02_classify_sessions.py` |
| Stdin-to-file deliveries | 4,117 | 4,174 non-download-delivery sessions | C16 | `queries/09_class_sources.py` |
| Non-download delivery after recon | 4,069 | 4,174 | C16 | `queries/02_classify_sessions.py` |
| Non-download delivery vs recon-then-fetch | 5.9 times (4,174 vs 712) | n/a | C16, C08 | `queries/02_classify_sessions.py` |

## Variations

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| Mirai-style (resembles) | 27 sessions, 6 sources; 26 with no recon | 27 | C18 | `queries/03_variations.py` |
| XorDDoS-style (resembles) | 381 sessions, 2 sources | n/a | C19 | `queries/03_variations.py` |
| Outlaw-style | not observed (0) | n/a | C20 | `queries/03_variations.py` |
| ShellBot curl \| perl | not observed (0) | n/a | C21 | `queries/03_variations.py` |
| Fileless curl \| sh (resembles) | 373 sessions, 10 sources | n/a | C22 | `queries/03_variations.py` |

## Rules (logic approximated on honeypot command transcripts)

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| sigma check errors, all three rules | 0 (plus 1 filename lint on hunt.yml) | 3 rules | C23 | `queries/05_sigma_check.sh` |
| Research matches | 69,979 (100%) | 69,979 | C24 | `queries/06_rule_approximation.py` |
| Hunt matches | 6,125 (8.75%) | 69,979 | C24 | `queries/06_rule_approximation.py` |
| Analyst matches | 845 (1.21%) | 69,979 | C24 | `queries/06_rule_approximation.py` |
| Analyst matches with no recon | 130 (15.38%) | 845 analyst matches | C25 | `queries/06_rule_approximation.py` |
| Busybox fetch sessions | 72 | 69,979 | C26b | `queries/06_rule_approximation.py` |
| Proposed correlation matches | 712 (1.02%) | 69,979 | C27 | `queries/06_rule_approximation.py` |
| Sibling (recon then any staging step) matches | 4,782 (6.83%) | 69,979 | C28 | `queries/06_rule_approximation.py` |
| Upstream validator errors (with rule copies) | 1 (EmulationScript.File) | n/a | C29 | `queries/08_upstream_validate.sh` |

## Task B: the earlier report (its window: operator addresses excluded, sessions up to 2026-09-21T16:22:36Z)

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| Report population reproduced | 136,113 sessions / 6,145 IPs / 69,440 with commands / 414,083 commands | n/a | B01 | `queries/21_audit_probes.py` |
| Published total commands | 414,083 | n/a | B02 | `queries/20_published_counts_audit.py` |
| Collapsed total commands | 370,448 (304,086 submitted lines) | n/a | B02 | `queries/20_published_counts_audit.py` |
| Inflation of the total | 43,635 (10.5%) | 414,083 published | B02 | `queries/20_published_counts_audit.py` |
| Top-command rank 7, collapsed | 0 (published 10,218) | n/a | B03 | `queries/20_published_counts_audit.py` |
| "93-command script", collapsed | 81 commands per session | 3,208 sessions with command_count = 93 | B06 | `queries/20_published_counts_audit.py` |
| "3,470 miner sessions" | could not be reproduced | n/a | B06 | `queries/21_audit_probes.py` |
| "crontab manipulation 3,605" | could not be reproduced | n/a | B05 | `queries/20_published_counts_audit.py` |
| MITRE rows unchanged after collapse | 16 (T1548.003: 29 → 28) | 17 rows | B07 | `queries/20_published_counts_audit.py` |
| Dashboard `cd` bucket, raw vs collapsed | 28,063 vs 14,167 | n/a | B08 | `queries/20_published_counts_audit.py` |

## Task C: land and run

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| Sessions with any land-and-run event | 5,224 (7.47%) | 69,979 sessions with commands | L01 | `queries/30_land_and_run.py` |
| Write-probe-only sessions (not classified) | 364 | 69,979 | L01 | `queries/30_land_and_run.py` |
| Staged, then executed | 4,703 (90.03%), 619 sources | 5,224 | L02 | `queries/30_land_and_run.py` |
| In-memory stage-and-run | 190 (3.64%), 10 sources | 5,224 | L02, L09 | `queries/30_land_and_run.py` |
| Staged, never executed | 124 (2.37%), 68 sources | 5,224 | L02 | `queries/30_land_and_run.py` |
| Executed, no staging | 3 (0.06%), 2 sources | 5,224 | L02 | `queries/30_land_and_run.py` |
| Execute-like, nothing new | 204 (3.91%), 127 sources | 5,224 | L02 | `queries/30_land_and_run.py` |
| Stage-then-execute including in-memory | 4,893 (93.66%) | 5,224 | L11 | `queries/30_land_and_run.py` |
| Cron-reference-only executes | 4,055 (86.22%) | 4,703 staged-then-executed sessions | L03 | `queries/30_land_and_run.py` |
| Direct in-session runs | 648 (13.78%) | 4,703 | L03 | `queries/30_land_and_run.py` |
| Stage to execute, any link (s), min / median / p90 / max | 0.00 / 15.55 / 18.38 / 125.67 | n = 4,703 | L04 | `queries/30_land_and_run.py` |
| Stage to direct run (s), min / median / p90 / max | 0.00 / 0.00 / 0.11 / 14.81 | n = 648 | L04 | `queries/30_land_and_run.py` |
| Same-session correlation, within 5 min and within 15 min | 4,703 and 4,703 | 4,703 | L05 | `queries/30_land_and_run.py` |
| `cat > file` sessions: direct run / cron reference only / none | 0 / 4,055 / 62 | 4,117 | L06 | `queries/30_land_and_run.py` |
| Staged-never-executed, run by the same source within 24 h | 4 | 124 | L07 | `queries/30_land_and_run.py` |
| Executed-no-staging with a same-source stage in another connection within 5 min | 2 | 3 | L08 | `queries/30_land_and_run.py` |
| Staged-then-executed sessions with no recon | 82 | 4,703 | L10 | `queries/30_land_and_run.py` |

## v3: final rules, correlation edge case, session semantics

| Figure | Value | Denominator | Ledger ID | Query |
|---|---|---|---|---|
| Final research.yml matches | 69,979 sessions (100%) · 942,292 events | 69,979 sessions with commands | R3-04 | `queries/06_rule_approximation.py` (final) |
| Final hunt.yml matches | 6,161 (8.80%) · 16,578 events | 69,979 | R3-02 | `queries/06_rule_approximation.py` (final) |
| Hunt, final vs draft | +36 sessions, +955 events | 6,125 draft sessions | R3-02 | `queries/42_rule_diff.py` |
| Final analyst.yml matches | 845 (1.21%) · 2,554 events | 69,979 | R3-03 | `queries/06_rule_approximation.py` (final) |
| Analyst, final vs draft | 0 sessions, +257 events (185 scp, 72 busybox) | 845 | R3-03 | `queries/42_rule_diff.py` |
| Final correlation matches | 712 (1.02%) | 69,979 | R3-05 | `queries/06_rule_approximation.py` (final) |
| Edge-case pair: `lscpu` → `curl` with no URL | 249.21 s (first targeted download: 326.78 s) | 1 session | R3-06 | `queries/41_correlation_edge_case.py` |
| Land-and-run hunt, command-text approximation (not a match count) | 392 sessions | 69,979 | R3-07 | `queries/43_land_run_text_approx.py` |
| Session rows / connect events | 141,186 / 141,186 | n/a | R3-10 | `queries/40_auth_session_semantics.py` |
| Rows with no disconnect event | 37 (33 key-probe orphans, 4 with commands) | 141,186 | R3-10 | `queries/40_auth_session_semantics.py` |
| Rows abandoned during the auth delay | 0 | 141,186 | R3-10 | `queries/40_auth_session_semantics.py` |
| Empty-password rows | 330 (0.23%) | 141,186 | R3-10 | `queries/40_auth_session_semantics.py` |
| Sessions with evidence of a channel (lower bound) | 69,979 (49.57%) | 141,186 | R3-11 | `queries/40_auth_session_semantics.py` |
| Public-key rows / with commands | 286 / 11 | n/a | R3-12 | `queries/40_auth_session_semantics.py` |
| Public-key rows in probe-then-signed-request connections | 66 rows in 33 connections | 286 | R3-12 | `queries/40_auth_session_semantics.py` |
| Derived connections / single-row | 141,117 / 141,053 | n/a | R3-13 | `queries/40_auth_session_semantics.py` |
| Upstream validator errors (Run B) | recon-burst 5, land-and-run 2; 0 of each with the proposed fixes | n/a | R3-14, R3-15 | `queries/44_upstream_validate_v3.sh`, `queries/47_validate_proposed_fixes.sh` |
