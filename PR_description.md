# Add lab validation: Linux writable-directory stage-and-execute chokepoint (auditd + Sysmon for Linux)

## Summary

This PR adds live-fire lab validation for the writable-directory stage-and-execute detection chokepoint on Linux. Two throwaway Azure VMs (Debian 12, Rocky 9), both running auditd + Sysmon for Linux, were subjected to an authorized assumed-breach exercise covering initial access, execution, persistence, defense evasion, lateral movement, and C2-tunneled exfiltration. Every validated land method generated `file_land`; every validated run method except `source` (BN-04, no new `execve`) generated `exec_log`. The revised T08 cron-spool write succeeded at script level but has no auditd receipt and is not telemetry-validated.

The chokepoint is field-grounded against three independently sourced wild specimens: C0XMO (Gafgyt variant), the Rocke cryptomining group, and UNC3944 (Scattered Spider), all of which follow the same stage-then-execute pattern in shared-writable directories.

The exercise also surfaced four coverage gaps that this PR documents rather than papers over.

## Chokepoint under test

Code that lands on a Linux host as a file in a shared-writable directory must be written before it can run. Two detection surfaces catch it:

1. **File write to a staging directory** — auditd `file_land` key on `/tmp`, `/dev/shm`, `/var/tmp`, `/var/spool/cron`, `/etc/cron.d`
2. **Process execution** — auditd `exec_log` key on the `execve` syscall

```
-a always,exit -F arch=b64 -S execve -F key=exec_log
-a always,exit -F arch=b32 -S execve -F key=exec_log
-w /tmp           -p wa -k file_land
-w /dev/shm       -p wa -k file_land
-w /var/tmp       -p wa -k file_land
-w /var/spool/cron -p wa -k file_land
-w /etc/cron.d    -p wa -k file_land
```

**Scope:** this covers file-backed staging only. Stdin-only execution (`curl | bash` with no file on disk) and memory-only execution (`memfd_create`) are out of scope.

## Threat grounding

**C0XMO (Gafgyt variant)** — SSH/Telnet/HTTP brute-force, `wget -O /tmp/.cache`, `chmod 777`, `./.cache`, `rm -f .cache`. Same chokepoint across three delivery protocols. The dot-prefixed staging in /tmp matches the analyst-tier Sigma rule. Source: [Fortinet](https://www.fortinet.com/blog/threat-research/inside-cross-platform-propagation-of-new-gafgyt-variant-c0xmo).

**Rocke group** — Payload staged to /var/tmp/kworkerds, cron persistence via /var/spool/cron/root and /etc/cron.d/root, SSH key harvesting from known_hosts for lateral movement. Covers the cron spool and lateral movement angles. Source: [Red Canary / Zscaler](https://www.zscaler.com/blogs/cybersecurity-best-practices/rocke-cryptominer), [Intezer](https://intezer.com/blog/rocke-group-actively-targeting-the-cloud-wants-your-ssh-keys/).

**UNC3944 (Scattered Spider)** — SCP ransomware to /tmp on ESXi hosts, chmod 0777, nohup with 4-hour sleep delay. Same staging chokepoint on ESXi as on Linux servers. Source: [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/defending-vsphere-from-unc3944/).

All three confirm the invariant holds across delivery protocols. SSH is one variation, not part of the universal pattern.

## Lab setup

| Host | OS / kernel | Monitoring |
|---|---|---|
| deb12 | Debian 12.8, 6.1.0-53-cloud-amd64 | auditd + Sysmon for Linux 1.5.3 |
| rocky9 | Rocky Linux 9.8, 5.14.0-687 | auditd + Sysmon for Linux 1.5.3 |

- SSH (22) was the only externally exposed service; inbound restricted to the operator IP.
- **Outbound-to-internet was denied at the network layer.** All C2 and payload transport that needed egress was tunneled through SSH reverse port forwards (`ssh -R`), so the firewall never saw outbound C2. This is the important part: **network-layer detection saw nothing; the host chokepoint fired on every variant.**
- Both VMs were snapshotted before testing and destroyed after.

## What was validated (evidence-backed)

Delivery/run pairs, each confirmed in target telemetry (auditd `file_land` + `exec_log`, Sysmon EID 1 command lines, and CHOKEPOINT markers on deb12):

| Land method | Run method | Detection path | Result |
|---|---|---|---|
| scp | bash | interpreter (Image=/usr/bin/bash, CommandLine has /tmp/) | caught (marker T01) |
| scp | chmod + exec | direct (Image=/tmp/t02.sh) | caught (marker T02) |
| heredoc | bash | interpreter | caught (marker T03) |
| base64 | decode + exec | interpreter | caught (marker T04) |
| echo pipe | source | gap — no new execve for sourced script (BN-04) | file_land only (marker T05) |
| python write | python3 | interpreter (Image=/usr/bin/python3, CommandLine has /tmp/) | caught (marker T_PY) |
| Sliver C2 upload → /dev/shm | execute via implant | direct (Image=/dev/shm/.cache) | caught |
| lateral scp (rocky → deb, 10.50.0.4) | nohup | direct (Image=/tmp/.svc) | caught on second hop |

**Detection path** distinguishes direct execution (staged file is the binary, Image matches staging path) from interpreter execution (Image is the interpreter, staged path visible in CommandLine only). The Sigma rules cover both paths.

Additional behaviors caught with command-line evidence:

- **Reverse shell** — `bash -i`, `python3 -c 'import pty;pty.spawn("/bin/bash")'` (Sysmon EID 1)
- **Timestomping** — `touch -r /usr/bin/ls /tmp/.update` (T1070.006)
- **Masquerade** — `cp /tmp/.update /tmp/systemd-helper` (T1036.005)
- **Cron persistence** — crontab write on Rocky; spool write on Debian (T1053.003)
- **Lateral movement** — `scp /tmp/.update sanc@10.50.0.4:/tmp/.svc` then remote exec (T1021.004 / T1570)
- **Exfil over C2** — `/etc/passwd` retrieved via Sliver `download`, transported over the SSH-tunneled channel (T1041)

**Key finding:** the lateral-movement hop proves the chokepoint is not limited to initial access — the same file-write + execve pattern fires on internal redeployment from a second host.

## Coverage gaps found (and what to add)

The exercise was only useful because it also found what the chokepoint **misses**. These are documented honestly:

1. **SSH-key persistence in home directories is not caught.** `authorized_keys` injection to `~/.ssh` produced **zero** `file_land` events, because the watch paths don't include home dirs. Recommend adding `-w /root/.ssh -p wa` and per-user `~/.ssh` equivalents (or an `authorized_keys`-targeted rule).
2. **Sensitive-file reads are invisible.** `cat /etc/shadow` generated only a generic `cat` execve with no target visibility; `file_land` is write/attr (`-p wa`) and doesn't watch `/etc/shadow`. Recommend a read watch (`-w /etc/shadow -p r`) or execve+path correlation.
3. **Noise drowns the signal.** Raw exec volume was dominated by system activity (dracut initramfs rebuild, `iptables`, `pidof`) — of ~38k total exec events across both hosts, only **~780 were attributable to the operator session**. A noise baseline (exclude `systemd-private-*` tmp churn and dracut initramfs paths) is needed before this is analyst-usable.
4. **Source builtin evades exec-based detection.** T05 used `source /tmp/t05.sh` — the script runs in the current bash process with no new execve. Only external commands called by the sourced script generate exec_log. file_land still catches the staging write.

## Detection alignment

The Sigma rules cover two execution paths:

- **Direct execution** (`selection_direct`): Image starts with a staging directory path. Catches chmod+exec binaries and implants.
- **Interpreter execution** (`selection_interpreter`): Image is a known interpreter (bash, sh, python3, python, perl) and CommandLine contains a staging directory path. Catches `bash /tmp/script.sh`, `python3 /tmp/payload.py`, etc.

These rules surface candidate events. Correlation of file_land and exec_log by host, staged path, and time window is performed at the hunt workflow level, not within the individual Sigma rules.

## Telemetry (labeled honestly)

| Metric | deb12 | rocky9 |
|---|---|---|
| auditd exec_log (total) | 8,598 | 29,566 |
| — operator-attributable | ~525 | ~252 |
| auditd file_land | 26 | 30 |
| CHOKEPOINT markers | 6 | 0 (implant-driven; markers only on deb12) |
| Sysmon lines | 5,753 | 36,070 |

Total captured log volume ≈ 80k lines; **operator-attributable exec events ≈ 780**. Both figures are reported to avoid overstating the attack footprint.

## Notes on rigor

- C2/reverse-shell callbacks were tunneled over the inbound SSH session; the egress DENY held and no outbound C2 was observed — the detection came entirely from the host, not the network.
- "Privilege escalation to root" in this lab used the operator's granted NOPASSWD sudo, not an exploited escalation; it is included only to show `auid` attribution survives the sudo transition.
- Full auditd (`exec_log`, `file_land`), Sysmon, marker logs, and system info for both hosts are attached in the evidence package. A per-claim reconciliation ledger accompanies this PR.

## ATT&CK v19 note

ATT&CK v19 (April 2026) split Defense Evasion (TA0005) into Stealth (TA0005) and Defense Impairment (TA0112). T1564.001 (Hidden Files and Directories), tagged in the analyst rule, falls under Stealth. The analyst rule uses attack.stealth for T1564.001, as required by the repository's pinned validator.

---

## Chokepoint Submission

- [x] YAML entry at `chokepoints/execution/ssh-land-and-run.yml` with all required fields
- [x] Unique UUIDv4 generated for `Id` field
- [x] All MITRE IDs verified against current ATT&CK framework
- [x] `AttackerControls` and `AttackerCannotControl` lists filled in
- [x] Chokepoint stages include `Input`, `Invariant`, `Observable`, `WhyCantBypass`
- [x] Scope exclusions documented (stdin-only, memory-only, source builtin)
- [x] Research sigma rule at `sigma-rules/ssh-land-and-run/research.yml`
- [x] Hunt sigma rule at `sigma-rules/ssh-land-and-run/hunt.yml` (direct + interpreter paths)
- [x] Analyst sigma rule at `sigma-rules/ssh-land-and-run/analyst.yml` (direct + interpreter paths)
- [x] Threat narratives: C0XMO (Fortinet), Rocke (Red Canary / Zscaler), and UNC3944 (Google/Mandiant)
- [x] At least one source reference included
- [x] All IOCs defanged
- [x] CHANGELOG.md updated
- [x] Emulation script at `emulation/ssh-land-and-run/emulate.sh`

## What is the chokepoint?

Code that lands on a Linux host as a file in a shared-writable directory (`/tmp`, `/dev/shm`, `/var/tmp`, `/var/spool/cron`) must be written before it can be consumed. Direct execution generates `execve`; interpreter consumption may instead expose the staged path in command-line or file-read telemetry. This covers file-backed staging only.

## Why can't attackers bypass this condition?

The file write is unavoidable for this scoped behavior, and the staged artifact must later be consumed to have an effect. Delivery and launch methods can rotate, but those conditions remain. Observability depends on configured telemetry: direct execution produces `execve`; interpreter launches can expose the path in command-line telemetry; and a sourced script using only shell builtins requires file-read monitoring. That `source` gap is documented as BN-04.

## Test environment / validation

Two throwaway Azure VMs (Debian 12, Rocky 9) with auditd + Sysmon for Linux. Outbound firewalled — all C2 tunnelled via SSH reverse forwards. Seven current marker variants, a Sliver C2 implant, a reverse shell, and lateral movement were telemetry-validated; revised T08 has script-success evidence only. ~80k log lines captured, ~780 operator-attributable exec events. Field-grounded against C0XMO, Rocke, and UNC3944. The sanitized evidence subset and per-claim reconciliation ledger are committed under `evidence/land-and-run/`.

---

*Lab validated 2026-09-28. Author: Jenna Frank. Co-conspirator: SancLogic (red-team execution, authorized simulated activity).*
