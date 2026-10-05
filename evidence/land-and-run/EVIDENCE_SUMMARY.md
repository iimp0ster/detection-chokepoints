# Evidence Summary v3: SSH honeypot vs. the revised chokepoint package

v3 closes the evidence gaps from the reviewer's check of the revised package. It covers the same snapshot and window as v2 (2026-04-27 to 2026-09-26 UTC, 153 calendar days), and operator sessions are excluded (107 sessions). Every v3 change is in `CHANGES.md`. The v2 summary follows unchanged, below the line.

## Round-3 results

1. **The final rules, re-approximated** (`rule_checks.md`). `queries/06_rule_approximation.py` now reads each rule's YAML detection block and reproduces v2's draft numbers exactly. The final rules match as follows (denominator: 69,979 sessions with commands):

   | Rule | Sessions | % | Events | Change from the draft |
   |---|---|---|---|---|
   | research | 69,979 | 100% | 942,292 | none |
   | hunt | 6,161 | 8.80% | 16,578 | +36 sessions, +955 events, from `nproc`/`free` and grep of cpuinfo/meminfo |
   | analyst | 845 | 1.21% | 2,554 | +257 events (scp client, busybox), no new sessions |
   | recon-then-fetch correlation | 712 | 1.02% | n/a | none |

   - **Correlation grouping:** approximated as Computer (one constant host) + LogonId (= session_id). The final file's `group-by` lists only `LogonId`.
   - **Land-and-run rules:** none can be match-counted, because the sensor has no file or process events. A labelled command-text approximation of the hunt tier finds text in 392 sessions. It is not a detection estimate.
2. **The 712th correlation match** (`samples/correlation_edge_case.md`).
   - In session `c51478eb-…`, the correlation paired `lscpu` (+6.71 s) with a `curl` that had **no URL** (+255.93 s). The gap is 249.21 s.
   - The first download *with a target* came at +333.49 s, which is 326.78 s after the recon. There is no later recon.
   - Both 711 and 712 are right. They use different definitions of a download, so nothing was fixed. The correlation's description sentence should say so.
3. **Session and authentication semantics** (`auth_and_session_semantics.md`).
   - A session row, its `session_id` and its `connect` event are created inside the accepted-credential callback, after the 1–3 s delay. That is neither TCP connect nor channel open, and neither of those is recorded.
   - Public-key rows are created on the key *offer*, before any signature check. The 286 "public-key logins" are accepted key offers, not completed authentications; only 11 ran commands.
   - 37 rows have no disconnect event (33 key-probe orphans, 4 with commands). **0** rows were abandoned during the auth delay.
   - At least 69,979 of 141,186 sessions (49.57%) opened a channel.
   - Recommended wording for "session" and "authentication" is in that file.
4. **The upstream validator on both revised entries** (`validator_results.md`, clone at 7c5c119).
   - **recon-burst: 5 errors.** Three are `Validation.TestedOn` required, because `State` isn't "Not yet recorded". Two are `ExpectedFPRate 'Unknown'`.
   - **land-and-run: 2 errors,** both `ExpectedFPRate 'Unknown'`.
   - **No errors** for the removed `EvolutionTimeline` or the free-text `FirstSeen` values.
   - **Proposed fixes:** `State: Not yet recorded` and `ExpectedFPRate: 'Low-High (not measured: no benign baseline)'`. With them, both entries pass on scratch copies.
   - **Also found:** the land-and-run Hunt stage's `SigmaRef` points to research.yml.
5. **Raw records for the two land-and-run RawLogs samples** (`samples/rawlogs_candidates.md`, records 6a, 6b and 7): `events.id` 9422 and 9428 (`cat > "w.sh"` part and whole-line echo) and 786044 (`perl /tmp/solid.pl …`).

## v3 output scan (the shareable zip)

Script: `queries/12_scan_outputs.py`, the same scan as v1 and v2. In v3 it counts scanned files exactly. It ran over **every file in `evidence-pack-v3-share.zip`** (staged before zipping): 96 files and about 10.6 MB, plus the report itself, 97 files in the zip. Full report: `results/scan_report.txt`.

**Exact-value checks:**

| Check | Result |
|---|---|
| All 6,617 source IPs | **0 hits** |
| The 25 other IPv4 addresses seen in commands | **0 hits** |
| The 4 operator addresses | **0 hits** |
| The 53,611 passwords of 6 or more characters | 427 distinct values matched, all reviewed privately |
| The 4,390 shorter passwords | **Not tested** |

The 427 password matches break down like this:

- **229 are digit runs** in timestamps and IDs.
- **The rest are ordinary words** (`session`, `Computer`, `password`, …), plus attacker file names such as `ohshit.sh`.
- **None** appears as a credential.

**Pattern checks:**

- **0 hits:** IPv4-shaped tokens, private keys, SSH keys, e-mail addresses, and the excluded script's name.
- **Local paths:** hits only in the scanner's own pattern list.
- **Base64 pattern:** it matched the two SHA-256 hashes in `README.md`. These are file checksums, not secrets.
- **Undefanged URLs:** reference links only.
- **Operator identity terms:** found in the 7 final rule files (`rules_final/`), whose `author` field carries the operator's name.
  - That authorship line is part of your rule files. They were copied unedited, as instructed.
  - To keep your name out of the zip, drop `rules_final/` and give reviewers the rules through the PR instead, or change the author field in your files.

**Excluded from the zip:** `private/` (pseudonym map, operator list, look-alike list, scan review), the snapshot database, `events.jsonl`, the chokepoint entry YAMLs, the emulation scripts and `.DS_Store` files.

---

# (v2) Evidence Summary v2: SSH honeypot vs. `ssh-post-auth-recon-burst`

v2 of the pack. It covers the same snapshot and the same window as v1: 2026-04-27 to 2026-09-26 UTC, 153 calendar days, ending with the last session at 2026-09-26T14:24:07Z.

What's new in v2:

- **Operator sessions are excluded.** That removed 107 sessions from the four operator addresses.
- **An audit of the published counts:** the command numbers in the earlier threat-intel report are checked against the sensor's double-logging (`published_counts_audit.md`).
- **A test of "land and run"** (`land_and_run.md`).

Every difference from v1 is in `CHANGES.md`. Every figure a write-up would cite is in `FINAL_NUMBERS.md`, each with its denominator, ledger ID and query.

**The short answer.**

- **Recon-then-fetch is real but narrow.**
  - 712 of 69,979 sessions with commands (1.02%).
  - 13 sources.
  - The three largest shapes account for 96.49% of those sessions and come from 4 sources.
  - It is not a chokepoint. 130 of the 842 fetching sessions (15.44%) skip recon, and 4,174 sessions stage code with no download utility at all.
- **"Stage, then execute" describes this data much better.** 4,703 sessions staged a file and then executed it, and 4,893 including in-memory runs. That is 93.66% of the 5,224 sessions with any stage or execute activity.
- **It is only a partial detection.** 4,055 of those 4,703 "execute" only by naming the file in a cron line, and some bots stage in one SSH connection and run in the next.
- **The earlier report was inflated.** Its "414,083 commands" is inflated by the double-logging by 43,635 (10.5%). Top-command rank 7 is an echo artefact. Its MITRE table is not inflated, apart from one row that is off by 1.

---

## Step 1: Sensor and schema (from reading the code first)

| Item | What the code says |
|---|---|
| Sensor | Custom Python SSH honeypot on **asyncssh** (not paramiko), with an emulated shell. The lure is a Solana validator on an Azure VM. Code: `the-honeypots/honeypot/` (`server.py`, `shell.py`, `session.py`, `logger.py`, `db.py`, `mitre.py`). |
| Authentication | **Every** password and public key is accepted after a random 1 to 3 s delay. Failed authentications are not logged. |
| Session unit | One SSH connection is one `SessionState`, one `sessions` row and one `session_id`. Several exec channels on one connection share it. |
| Command capture | The string the client sent: one exec request, or one interactive line. `sudo ` is stripped. |
| Chain double-logging | Lines joined by `; ` or ` && ` are logged per part **and** again as the whole line. The analysis collapses the whole-line echoes (`hp_lib.rebuild`): 49,441 collapsed out of 454,168 command events (operator sessions excluded). |
| Chain splitting | The split does not respect quotes. The emulated shell's replies changed the behaviour of at least one bot family (`samples/counterexamples.md`, section 4). |
| Execution | Nothing runs. `wget` and `curl` show a fake "malware injection" screen lasting about 7.3 s. **No file is ever downloaded**, so each "fetch" is an attempted command. Bytes sent on stdin (for example after `cat > file`) are **not captured**. |
| Timestamps | UTC ISO-8601 with microseconds, recorded when the emulation *finished*, not when the command arrived. Durations are in seconds. |
| Storage | SQLite with four tables: `sessions`, `events`, `easter_egg_hits` and `ip_cache`. It is mirrored to `events.jsonl`, and the event types are `connect`, `command`, `disconnect`, `enrichment` and `easter_egg`. |
| `connection_type` | Defaults to `interactive` until a channel opens. The `connect` event always says `interactive`. The `sessions` row is updated to `exec` when an exec request arrives. |
| Process telemetry | **None.** There is no Image, ParentImage, PID or file events. The Sigma rules (`process_creation`) cannot be run as written. |

### Source of truth

- **Every metric** uses the SQLite snapshot (`honeypot_snapshot_20260926.db`, opened with `mode=ro&immutable=1`).
- **Cross-check:** `events.jsonl` holds exactly the same counts by event type up to the snapshot's last event, with a difference of 0 for every type. It also holds 1,463 later events (up to 2026-09-27T02:03Z), which are excluded. Nothing is counted twice.

### Code version

- The code was read at repo commit `adc8fd7`.
- The chain-splitting and wget/curl code is unchanged between the repo's two sensor commits (`d8ccefc` on 2026-04-28 and `5f83145` on 2026-09-19).
- The build deployed on the VM was not diffed against the repo.

## Step 2: Core counts (operator sessions excluded)

Script: `queries/01_sources_and_counts.py`. Output: `results/core_counts.json`.

| Metric | Value |
|---|---|
| Window | 2026-04-27T23:09:48Z to 2026-09-26T14:24:07Z. **153 calendar days** inclusive (151.63 elapsed). |
| Removed by the operator exclusion | **107 sessions; 739 events** (command 390, connect 107, enrichment 107, disconnect 83, easter_egg 52). 77 of the removed sessions had commands. |
| Sessions | 141,186 |
| Distinct source IPs | 6,613 |
| Sessions with at least one command event | 69,979 (49.57% of 141,186) |
| Sessions with no commands | 71,207 |
| `sessions.connection_type` | exec 69,898 · interactive 71,288 ("interactive" includes sessions that never opened a channel) |
| Public-key logins | 286 |
| Events | 886,494 in total: command 454,168 · connect 141,186 · enrichment 141,186 · disconnect 141,149 · easter_egg 8,805 |
| Command events, whole-line echoes collapsed | 49,441 echoes removed, leaving 331,340 submitted lines and 404,727 atomic commands |

**Possible further operator addresses:** six sources show signals that could mean operator testing (exploring the lure files, or test domains). None of them started within 30 minutes of an operator session, and none shares an operator ASN or ISP. They are listed **privately** for confirmation and are **not** excluded (`queries/13_operator_lookalikes.py`).

## Step 3: Session classes

Script: `queries/02_classify_sessions.py`. Outputs: `results/classification.json`, `results/session_classes.csv` and `results/class_sources.json`. The definitions are unchanged from v1 (see `queries/hp_lib.py`):

- **recon:** exactly hunt.yml's selections
- **fetch:** wget, curl, tftp or ftpget with a remote-looking target
- **non-download delivery:** `cat > file`, `scp -t`, `/dev/tcp` or base64

Denominator: **69,979 sessions with commands**.

| Class | Sessions | % of 69,979 | Distinct sources |
|---|---|---|---|
| Recon then fetch | 712 | 1.02% | 13 |
| Fetch with no recon | 130 | 0.19% | 18 |
| **Fetch then recon** | **0** | 0.00% | 0 |
| Recon only | 1,344 | 1.92% | 448 |
| Non-download delivery | 4,174 | 5.96% | 632 |
| None of the above | 63,619 | 90.91% | 88 |

- **Fetch then recon: confirmed at 0.** The one v1 session was the operator's own test.
- **Broader recon definition:** recon then fetch stays at 712, recon only becomes 1,358, and fetch then recon stays at 0.
- **Recon before fetch:** of the 842 sessions that attempted a download utility, 712 (84.56%) ran recon first and 130 (15.44%) never did.

### Recon-then-fetch detail (n = 712)

| Interval (seconds) | min | median | p90 | max |
|---|---|---|---|---|
| Login accepted to first recon | 0.09 | 0.31 | 0.43 | 19.62 |
| First recon to first fetch | 0.00 | 0.00 | 0.29 | 326.78 |
| Login accepted to first fetch | 0.23 | 0.39 | 0.73 | 333.49 |

- **Same request:** 689 of 712 sessions sent recon and fetch in one exec request.
- **Timing window:** 711 of 712 fetched within 300 s of the first recon.
- **Sequences:** 16 distinct command-name sequences, and 18 distinct transcripts after abstraction.
- **Concentration:** the three largest shapes cover **687 of 712 sessions (96.49%) from 4 sources**.
- **Recon is rarely a burst:** before the first fetch, **319 of 712 (44.80%)** ran exactly one recon command; 4 ran two, 3 ran three, 381 ran four, and 5 ran five or more.

## Step 4: Counterexamples

See **`samples/counterexamples.md`**. The transcripts are unchanged from v1 (none of them came from an operator session). The counts in the section headings are updated, and fetch-then-recon now shows 0.

## Step 5: The five Variations

Script: `queries/03_variations.py`. None of these results changed, because no operator session matched any variation.

| Variation | Result | Sessions (sources) |
|---|---|---|
| Mirai-style busybox loader | Resembles | 27 (6). 26 of the 27 ran no recon. |
| XorDDoS-style curl dropper | Resembles | 381 (2), all recon then fetch |
| Outlaw-style miner/scanner | **Not observed** as described | 0. Partial markers only. |
| ShellBot curl \| perl | **Not observed** | 0 |
| Fileless curl \| sh | Resembles | 373 (10), plus 3 `sh -c "$(curl …)"` |

## Step 6: Raw-log candidates

See **`samples/rawlogs_candidates.md`**. It is unchanged. The candidates are sanitised honeypot JSON event records, labelled as such, not auditd or Sysmon. None comes from an operator session.

## Step 7: Rule checks

See **`rule_checks.md`**. `sigma check` found 0 errors and 0 condition errors in all three rules and in the proposed correlation, plus the `hunt.yml` filename lint.

Rule logic approximated on honeypot command transcripts (denominator 69,979):

| Rule | Sessions matched | % |
|---|---|---|
| Research | 69,979 | 100% by construction |
| Hunt | 6,125 | 8.75% |
| Analyst | 845 | 1.21%. 130 of these (15.38%) had no recon. |
| Proposed correlation (hunt then analyst, 5 min) | **712** | 1.02%. Exactly the 712 recon-then-fetch sessions, and nothing else. |
| Sibling (recon then any staging step, 5 min) | 4,782 | 6.83% |

## Step 8: Upstream validator (optional step, done)

- **Upstream commit:** `iimp0ster/detection-chokepoints` at `7c5c11946034d6a04cdaaf1cb1f9414c138865ec`.
- **How it was run:** read-only clone, push URL disabled. `scripts/validate_schema.py` ran on a **copy** of the YAML placed in the clone's `drafts/execution/`.
- **Result:** with copies of the three rules at the SigmaRef paths, one error remains: `EmulationScript.File must resolve to an existing repository file`. The emulation script was neither copied nor run.
- **Placeholders:** the validator does not flag the `REPLACE WITH REAL CAPTURE` placeholders.
- Nothing was committed, pushed or forked, and no PR was opened.

---

## Task B: The earlier report's counts and the double-logging

See **`published_counts_audit.md`**.

The report's population reproduces **exactly** with the operator addresses excluded and a cutoff at 2026-09-21T16:22:36Z:

| Figure | Published | Reproduced |
|---|---|---|
| Sessions | 136,113 | 136,113 |
| IPs | 6,145 | 6,145 |
| Sessions with commands | 69,440 | 69,440 |
| Commands | 414,083 | 414,083 |

What the audit found:

- **"414,083 commands" is inflated.** It is `SUM(command_count)`, echoes included. Collapsed, it is **370,448** (+43,635, or 10.5% of 414,083).
- **Top command rank 7 is itself an echo.** Collapsed, it is 0. The other nine ranks are exact and not inflated.
- **"93-command script":** the script is 81 commands. The "3,470 sessions" figure could not be reproduced.
- **"crontab manipulation 3,605"** could not be reproduced by any definition tried.
- **The MITRE table** counts sessions, and tags are deduplicated per session. 16 of 17 rows are unaffected; T1548.003 drops from 29 to 28. Per-event tag counts *would* be doubled.
- **The dashboard** uses the same inflated `SUM(command_count)`, and its first-word command chart is inflated too (for example, `cd` is 28,063 raw vs 14,167 collapsed).

## Task C: Land and run

See **`land_and_run.md`**, with examples in `samples/land_and_run_examples.md`.

Of 69,979 sessions with commands, **5,224** (7.47%) have a stage, in-memory, execute or execute-like event:

| Class | Sessions | Sources |
|---|---|---|
| Staged, then executed (same session) | 4,703 | 619 |
| In-memory stage-and-run | 190 | 10 |
| Staged, never executed in the session | 124 | 68 |
| Executed with no staging in the session | 3 | 2 |
| Execute-like, nothing new | 204 | 127 |

**Timing, stage to execute** (seconds):

| Link | n | min | median | p90 | max |
|---|---|---|---|---|---|
| Any link | 4,703 | 0.00 | 15.55 | 18.38 | 125.67 |
| Direct runs only | 648 | 0.00 | 0.00 | 0.11 | 14.81 |

**Same-session correlation:** it catches 4,703 of 4,703 within both 5 and 15 minutes.

**But only 648 are direct runs.** 4,055 (86.22%) "execute" only through a cron line, which on a real host runs outside the SSH session (inferred).

**The 4,117 `cat > file` sessions:**

- direct run of the written file: 0
- cron reference only: 4,055
- no linked execute: 62

**Staged, never executed (124):** 4 were run by the same source within 24 h. Stage and run can also be split across SSH connections: `src-5063` pushed with `scp -t`, then ran the payload 3 s later in a new connection.

## Honest read

**Recon-then-fetch** is a good hunt pattern and a clean correlation for a narrow, repetitive slice: 712 sessions, 13 sources. It is not a chokepoint.

- **Recon is optional:** 130 of the 842 fetching sessions (15.44%) had none.
- **Download utilities can be bypassed:** 4,174 sessions staged code through stdin or scp.
- **Recon is usually one command, not a burst:** 44.80% of recon-then-fetch sessions ran exactly one.

**"Stage, then execute"** holds up much better as a description: 93.66% of 5,224 land-and-run sessions, with no recon required, and it survives every transfer method seen. **It does not hold up as a same-session rule**, for four reasons:

- Most execution is deferred to cron.
- Some bots split the stage and the run across connections.
- In-memory runs leave no file.
- Nothing actually ran here.

The constant worth testing next is **"a file written by an SSH-session process is later executed by any process"**, joined on the file path. It needs auditd `execve` plus file-create events, or Sysmon for Linux EID 1 and EID 11, on real or high-interaction hosts.

## Limits that apply to every number above

- **No benign baseline.** A honeypot sees only attackers (and, before exclusion, the operator), so false-positive rates can't be measured.
- **Command strings only, from an emulated shell.** Nothing ran. stdin and scp payloads are **not captured**, and bots reacted to fake output.
- **Every login is accepted.** Failed authentications are **not captured**.
- **Timestamps are emulation-completion times.**
- **Classifications are text rules**, listed in full in `queries/hp_lib.py`.
- **The six possible further operator addresses are still included** until the operator confirms them.

## Private source pack and published subset

The original private `evidence-pack-v2/` contains the complete analysis set
listed below. This PR intentionally publishes only the land-and-run subset:
the two counting modules, aggregate result, claims ledger, sanitized lab-log
archives, and the T08 rerun receipt. Paths listed below which are absent from
`evidence/land-and-run/` remain private provenance and are not represented as
committed artifacts.

### Published in this PR

| Path | What it is |
|---|---|
| `EVIDENCE_SUMMARY.md` | This methodology and provenance summary |
| `FINAL_NUMBERS.md` | Citable figures, denominators, ledger IDs, and queries |
| `claims_ledger.csv` | Claim-level evidence states and limitations |
| `queries/30_land_and_run.py`, `queries/hp_lib.py` | Land-and-run counting logic |
| `results/land_and_run.json` | Sanitized aggregate result |
| `lab/chokepoint_evidence_*.tar.gz` | Sanitized auditd and Sysmon lab logs rendered by the page |
| `lab/emulate-receipt-t08-rerun.txt` | Current-script stdout; not an auditd validation receipt |

### Original private pack contents

| Path | What it is |
|---|---|
| `EVIDENCE_SUMMARY.md` | This file (the v3 round-3 section, then the v2 summary) |
| `auth_and_session_semantics.md` | v3 task 3 |
| `validator_results.md` | v3 task 4 |
| `samples/correlation_edge_case.md` | v3 task 2 |
| `FINAL_NUMBERS.md` | Every citable figure, with value, denominator, ledger ID and query |
| `CHANGES.md` | Every difference from v1 |
| `claims_ledger.csv` | Ledger (71 claims: 54 from v2 plus R3-01 to R3-17) |
| `claims_ledger_v1_historical.csv` | v1 ledger, unchanged |
| `rule_checks.md` | Schema checks, approximations, gaps and proposals (v2 numbers) |
| `published_counts_audit.md` | Task B |
| `land_and_run.md` | Task C |
| `samples/` | counterexamples, land-and-run examples, raw-log candidates |
| `queries/` | Every script, plus `run_all.sh` and `README.md` |
| `results/` | Script outputs |
| `rules_under_test/`, `chokepoint_under_test/` | Unmodified copies of the draft |
| `proposed/` | Proposed correlation rule |

The pseudonym map, the operator list, the look-alike review list and the scan review file are stored **outside** the pack.

## Output scan

Private-pack script: `queries/12_scan_outputs.py`, the same scan as v1. It was
run on 2026-09-26 over **all of the private v2 pack**. The full report remains
private at `results/scan_report.txt`; this section records its results.

**What the scan covered:**

- Every file under `evidence-pack-v2/`, recursively: 64 files, about 10.5 MB. That includes every script, template, result file and both per-session CSVs.
- The report file itself was not scanned.
- macOS `.DS_Store` files and `__pycache__` folders were deleted first.

**Exact-value checks** (matched against the real values in the snapshot, as whole tokens):

| Check | What was searched for | Result |
|---|---|---|
| Source IPs | All 6,617 source IPs, including the operator addresses and the six possible further operator sources | **0 hits** |
| Other IPs | All 25 other IPv4 addresses seen inside commands | **0 hits** |
| Operator addresses | The 4 operator addresses | **0 hits** |
| Passwords | The 53,611 distinct passwords of 6 or more characters | 417 distinct values matched. All were reviewed privately. See below. |
| Short passwords | The 4,390 shorter passwords | **Not tested**; they are too generic |

The 417 password matches break down like this:

- **229 are digit runs** inside timestamps and IDs, in the result CSVs and JSON.
- **The rest are ordinary words** that attackers also tried as passwords (`session`, `command`, `solana`, …), plus 3 attacker **file names** in `results/land_run_sessions.csv` (`anonymous`, `ohshit.sh`, `phantom.sh`).
- **None** appears as a credential.

**Pattern checks:**

| Pattern | Result |
|---|---|
| IPv4-shaped tokens | **0 hits** |
| Private-key blocks, SSH keys, base64 runs of 60 or more characters | **0 hits** |
| Local paths | Hits only in the scanner's own pattern list |
| Operator name, handle and e-mail strings (from a private list) | **0 hits** |
| Any e-mail address | **0 hits** |
| The excluded metrics script's name (from a private list) | **0 hits**, after the fix below |
| Undefanged `http(s)`/`ftp` | Reference links only: attack.mitre.org, vendor pages, the upstream GitHub clone URL, and a regex in `02_classify_sessions.py` |

No attacker URL or domain appears undefanged.

**Fixed during the scan:**

- `published_counts_audit.md` named the excluded metrics script and quoted its cutoff. Both are now removed.
- `queries/22_find_report_source.sh` had hardcoded local folder names. It now takes the folders as arguments.

**Not covered:**

- Obfuscated or encoded secrets beyond the base64 rule.
- Passwords under 6 characters.
- Anything outside the pack. The private folder holds the pseudonym map, the operator list, the look-alike review list and the scan review file; it is outside the pack on purpose.

At the time of that scan, nothing had been published or pushed and no PR had
been opened. This PR subsequently publishes the reduced, sanitized subset
identified above.
