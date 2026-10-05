"""Task C: test the 'land and run' hypothesis (stage, then execute).

Events come from hp_lib.land_run_events(). A stage is LINKED to an execute when
the execute's normalised name (hp_lib.norm_name: quotes, ./, directory prefixes
such as /tmp/ ~/ /dev/shm/ stripped; basename compared exactly) equals the name
of a stage event that occurs EARLIER in the same session (segment order). A
rename (mv/cp of a staged name) carries the link to the new name.

Classes (every session with at least one stage/inmem/exec/execlike event; first
match wins; operator sessions excluded; recon NOT required):
  staged_then_executed    a linked stage -> execute pair (direct run or cron/unit reference)
  in_memory               fetch/decode piped into an interpreter, or sh -c "$(curl ...)"
  staged_never_executed   stage event(s), none linked to a later execute in the session
  executed_no_staging     execute of a non-system path or script file, nothing staged
  execute_like_nothing_new  only interpreter one-liners, reverse-shell forms or system binaries by path

Writes ../results/land_and_run.json and ../results/land_run_sessions.csv.
"""
import csv
import json
import os
import statistics
from collections import Counter, defaultdict
from datetime import timedelta

from hp_lib import *

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "..", "results")
CLASSES = ["staged_then_executed", "in_memory", "staged_never_executed", "executed_no_staging", "execute_like_nothing_new"]


def dist(xs):
    if not xs:
        return None
    xs = sorted(xs)
    return {"n": len(xs), "min": round(xs[0], 2), "median": round(statistics.median(xs), 2),
            "p90": round(xs[min(len(xs) - 1, int(round(0.9 * (len(xs) - 1))))], 2), "max": round(xs[-1], 2)}


def main():
    c = connect()
    P = Pseudo(c)
    v1cls = {r["session_id"]: r for r in csv.DictReader(open(os.path.join(RES, "session_classes.csv")))}
    rows, per_src_sessions = [], defaultdict(list)
    # sessions in non_download_delivery / none classes that still ran hunt-list recon
    recon_nd = set()
    for sid0, ip0, st0, ct0, ev0 in load_sessions(c):
        if ev0 and v1cls.get(sid0, {}).get("class_hunt") in ("non_download_delivery", "none_of_the_above"):
            l0, lv0, _ = rebuild(ev0)
            if any(is_hunt_recon(x[4], x[5]) for x in session_segments(l0, lv0)):
                recon_nd.add(sid0)
    counts, srcs = Counter(), defaultdict(set)
    overlap = Counter()
    gaps, link_kind = [], Counter()
    direct_gaps = []
    probe_only = 0
    recon_by_class = defaultdict(Counter)
    stage_methods = Counter()
    within = Counter()
    n_with_cmds = 0
    for sid, ip, st, ctype, ev in load_sessions(c):
        if not ev:
            continue
        n_with_cmds += 1
        lines, leaves, _ = rebuild(ev)
        evs = land_run_events(lines, leaves)
        src = P.s(ip)
        stages = [e for e in evs if e[2] == "stage"]
        inmem = [e for e in evs if e[2] == "inmem"]
        execs = [e for e in evs if e[2] in ("exec", "exec_persist")]
        execlike = [e for e in evs if e[2] == "execlike"]
        per_src_sessions[ip].append((ts(st), sid, {e[4] for e in stages if e[4]}, {e[4] for e in execs if e[4]}, bool(execs or execlike or inmem)))
        if not (stages or inmem or execs or execlike):
            if any(e[2] == "probe" for e in evs):
                probe_only += 1
            continue
        links = []
        for x in execs:
            s_ = [s for s in stages if s[4] and s[4] == x[4] and s[0] < x[0]]
            if s_:
                links.append((s_[0], x))
        if links:
            cls = "staged_then_executed"
        elif inmem:
            cls = "in_memory"
        elif stages:
            cls = "staged_never_executed"
        elif execs:
            cls = "executed_no_staging"
        else:
            cls = "execute_like_nothing_new"
        counts[cls] += 1
        srcs[cls].add(src)
        rc = v1cls.get(sid, {}).get("class_hunt", "")
        recon_by_class[cls]["hunt_recon_present" if rc in ("recon_then_fetch", "fetch_then_recon", "recon_only") or (rc == "non_download_delivery" and sid in recon_nd) else "no_hunt_recon"] += 1
        if links and inmem:
            overlap["staged_then_executed_and_in_memory"] += 1
        first_gap = None
        direct = [l for l in links if l[1][2] == "exec"]
        persist = [l for l in links if l[1][2] == "exec_persist"]
        if links:
            link_kind["direct_execute" if direct and not persist else "persistence_reference_only" if persist and not direct else "both"] += 1
            s0, x0 = min(links, key=lambda l: l[1][0])
            first_gap = (ts(x0[1]) - ts(s0[1])).total_seconds()
            gaps.append(first_gap)
            within["le_5min"] += first_gap <= 300
            within["le_15min"] += first_gap <= 900
            stage_methods[s0[3]] += 1
            if direct:
                sd, xd = min(direct, key=lambda l: l[1][0])
                direct_gaps.append((ts(xd[1]) - ts(sd[1])).total_seconds())
        rows.append({"session_id": sid, "src": src, "started_at": st, "class_land_run": cls,
                     "stage_methods": "|".join(sorted({e[3] for e in stages})),
                     "staged_names": "|".join(sorted({e[4] for e in stages if e[4]}))[:200],
                     "inmem_methods": "|".join(sorted({e[3] for e in inmem})),
                     "exec_methods": "|".join(sorted({e[3] for e in execs + execlike})),
                     "direct_link": int(bool(direct)), "persist_link": int(bool(persist)),
                     "stage_to_exec_s": round(first_gap, 3) if first_gap is not None else "",
                     "v2_recon_class": v1cls.get(sid, {}).get("class_hunt", ""),
                     "delivery_v1": v1cls.get(sid, {}).get("delivery", "")})

    # staged-never-executed: same source runs the name in a later session within 24 h?
    later = 0
    later_sids = []
    idx = {r["session_id"]: r for r in rows}
    for ip, ss in per_src_sessions.items():
        ss.sort()
        for k, (t0, sid, staged, _, _x) in enumerate(ss):
            r = idx.get(sid)
            if not r or r["class_land_run"] != "staged_never_executed" or not staged:
                continue
            for t1, sid1, _, ex1, _x1 in ss[k + 1:]:
                if t1 - t0 > timedelta(hours=24):
                    break
                if staged & ex1:
                    later += 1; later_sids.append(sid); break

    # Looser cross-session check (names ignored): a staged-never-executed session
    # followed by ANY execute-type event from the same source within 5 minutes, and
    # an executed-no-staging session preceded by a same-source stage within 5 minutes.
    cross_fwd, cross_back = 0, 0
    for ip, ss in per_src_sessions.items():
        for k, (t0, sid, staged, _, _x) in enumerate(ss):
            r = idx.get(sid)
            if not r:
                continue
            if r["class_land_run"] == "staged_never_executed":
                if any(0 < (t1 - t0).total_seconds() <= 300 and x1 for t1, _, _, _, x1 in ss[k + 1:]):
                    cross_fwd += 1
            if r["class_land_run"] == "executed_no_staging":
                if any(0 < (t0 - tp).total_seconds() <= 300 and st_ for tp, _, st_, _, _ in ss[:k]):
                    cross_back += 1

    # the 4,117 stdin-to-file sessions from the v1/v2 recon classification
    stdin_ids = [sid for sid, r in v1cls.items() if r["class_hunt"] == "non_download_delivery" and r["delivery"] == "stdin_to_file"]
    stdin = Counter()
    for sid in stdin_ids:
        r = idx.get(sid)
        if not r:
            stdin["no_land_run_events"] += 1
        elif r["direct_link"] == 1:
            stdin["direct_execute_of_staged_name"] += 1
        elif r["persist_link"] == 1:
            stdin["cron_or_unit_reference_only"] += 1
        else:
            stdin["no_linked_execute"] += 1

    with open(os.path.join(RES, "land_run_sessions.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    total = sum(counts.values())
    out = {
        "denominator_sessions_with_commands": n_with_cmds,
        "sessions_with_any_land_run_event": total,
        "classes": {k: {"sessions": counts[k], "sources": len(srcs[k]),
                        "pct_of_land_run_sessions": round(100 * counts[k] / total, 2) if total else None} for k in CLASSES},
        "overlap": dict(overlap),
        "staged_then_executed": {
            "link_kind": dict(link_kind),
            "first_stage_method": dict(stage_methods),
            "stage_to_execute_seconds": dist(gaps),
            "same_session_correlation_within_5min": within["le_5min"],
            "same_session_correlation_within_15min": within["le_15min"],
        },
        "staged_never_executed_run_by_same_source_within_24h": later,
        "cross_session_5min_any_name": {
            "staged_never_executed_followed_by_same_source_execute_event": cross_fwd,
            "executed_no_staging_preceded_by_same_source_stage": cross_back,
        },
        "direct_execute_only": {
            "sessions": len(direct_gaps),
            "stage_to_direct_execute_seconds": dist(direct_gaps),
            "within_5min": sum(g <= 300 for g in direct_gaps),
            "within_15min": sum(g <= 900 for g in direct_gaps),
        },
        "write_probe_only_sessions_not_classified": probe_only,
        "hunt_recon_presence_by_class": {k: dict(v) for k, v in recon_by_class.items()},
        "stdin_to_file_sessions_4117": {"n": len(stdin_ids), **dict(stdin)},
    }
    json.dump(out, open(os.path.join(RES, "land_and_run.json"), "w"), indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
