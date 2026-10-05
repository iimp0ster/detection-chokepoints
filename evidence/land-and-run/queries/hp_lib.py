"""Shared, read-only helpers for the SSH honeypot evidence pack.

Source of truth for every metric: the SQLite snapshot (sessions + events tables),
opened with mode=ro&immutable=1. events.jsonl is used only for the cross-check in
01_sources_and_counts.py.

Set HP_DB to the snapshot path before running, e.g.
  HP_DB=/path/to/honeypot_snapshot_20260926.db python3 02_classify_sessions.py
Nothing in this module executes, fetches or resolves anything from the data.
"""
import json
import os
import re
import sqlite3
from datetime import datetime

DB_PATH = os.environ.get("HP_DB", "honeypot_snapshot_20260926.db")

# v2: operator sessions are excluded by default (set HP_EXCLUDE_OPERATORS=0 to include).
# The four addresses are read from a private file kept outside the pack.
EXCLUDE_OPERATORS = os.environ.get("HP_EXCLUDE_OPERATORS", "1") == "1"
PRIVATE_DIR = os.environ.get("HP_PRIVATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "private"))
# Window end: same cutoff as v1 (last session in the snapshot).
WINDOW_END = os.environ.get("HP_WINDOW_END", "2026-09-26T14:24:07.581485+00:00")


def operator_ips():
    with open(os.path.join(PRIVATE_DIR, "operator_ips.txt")) as fh:
        return set(fh.read().split())


def excluded_ips():
    return operator_ips() if EXCLUDE_OPERATORS else set()


def connect():
    uri = "file:" + os.path.abspath(DB_PATH) + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def ts(s):
    return datetime.fromisoformat(s)


# ── 1. Undo the sensor's chain double-logging ──────────────────────────────
# shell.py _dispatch() splits a line on the first of " && " / "; " it finds,
# runs (and logs) each part, and then execute() logs the whole line as well.
# So "a; b" is logged as: "a", "b", "a; b". Lines matching the tripwire regex
# or exit/logout are logged once without splitting. sudo is stripped first.
SENSOR_SEPS = [" && ", "; "]
TRIPWIRE = re.compile(r"^\s*(sudo\s+(su|bash|sh|-s|-i)|su\s*(root|-|$)|chmod\s+777|chattr)\b")
EXIT = re.compile(r"^\s*(exit|logout)\s*$")


def strip_sudo(t):
    m = re.match(r"^\s*sudo\s+(.+)$", t)
    return m.group(1).strip() if m else t


def direct_subs(t):
    if EXIT.match(t) or TRIPWIRE.match(t):
        return None
    for sep in SENSOR_SEPS:
        if sep in t:
            return [strip_sudo(s.strip()) for s in t.split(sep) if s.strip()]
    return None


def rebuild(cmd_events):
    """cmd_events: [(timestamp, text)] in insertion order for one session.
    Returns (lines, leaves). lines = what the client actually submitted
    (one per exec request or interactive line); leaves = the atomic commands
    the sensor ran, each with its own completion timestamp, in order.
    Also returns the number of parent echoes collapsed."""
    nodes = []  # each: {"text", "ts", "children"}
    collapsed = 0
    for t_s, text in cmd_events:
        subs = direct_subs(text)
        if subs and len(nodes) >= len(subs) and [n["text"] for n in nodes[-len(subs):]] == subs:
            kids = nodes[-len(subs):]
            del nodes[-len(subs):]
            nodes.append({"text": text, "ts": t_s, "children": kids})
            collapsed += 1
        else:
            nodes.append({"text": text, "ts": t_s, "children": []})

    leaves = []

    def walk(n):
        if n["children"]:
            for k in n["children"]:
                walk(k)
        else:
            leaves.append((n["ts"], n["text"]))

    for n in nodes:
        walk(n)
    lines = [(n["ts"], n["text"]) for n in nodes]
    return lines, leaves, collapsed


def parent_flags(texts):
    """Same algorithm as rebuild(), but returns one boolean per logged event:
    True when that event is a whole-line echo of parts logged just before it."""
    nodes = []  # (text, index)
    flags = [False] * len(texts)
    for i, text in enumerate(texts):
        subs = direct_subs(text)
        if subs and len(nodes) >= len(subs) and [n[0] for n in nodes[-len(subs):]] == subs:
            del nodes[-len(subs):]
            flags[i] = True
        nodes.append((text, i))
    return flags


# ── 2. Split a leaf into shell segments (quote-aware) ──────────────────────
def split_segments(text):
    """Split on ; && || | & and newlines outside quotes.
    Returns [(segment_text, joined_by)] where joined_by is the operator that
    preceded the segment ('' for the first, '|' for a pipe)."""
    out, buf, q, prev, i = [], [], None, "", 0
    while i < len(text):
        c = text[i]
        if q:
            buf.append(c)
            if c == "\\" and q == '"' and i + 1 < len(text):
                buf.append(text[i + 1]); i += 2; continue
            if c == q:
                q = None
            i += 1; continue
        if c in "'\"":
            q = c; buf.append(c); i += 1; continue
        two = text[i:i + 2]
        op = None
        if two in ("&&", "||"):
            op, step = two, 2
        elif c in ";\n":
            op, step = ";", 1
        elif c == "|":
            op, step = "|", 1
        elif c == "&" and not text[i + 1:i + 2] == ">" and not (i and text[i - 1] in "<>"):
            op, step = "&", 1
        if op:
            seg = "".join(buf).strip()
            if seg:
                out.append((seg, prev))
            buf, prev = [], op
            i += step; continue
        buf.append(c); i += 1
    seg = "".join(buf).strip()
    if seg:
        out.append((seg, prev))
    return out


WRAPPERS = {"sudo", "nohup", "exec", "command", "time", "nice", "setsid", "env", "busybox", "timeout", "stdbuf"}


def words(seg):
    try:
        import shlex
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def base_and_args(seg):
    """Return (base, args, via_busybox). Strips env assignments, wrappers,
    paths and a leading 'cd x &&' is already split off by split_segments."""
    w = words(seg)
    via_bb = False
    while w:
        head = w[0].split("/")[-1]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w[0]):
            w = w[1:]; continue
        if head in WRAPPERS:
            if head == "busybox":
                via_bb = True
            w = w[1:]
            if head == "timeout" and w and re.match(r"^\d+[smh]?$", w[0]):
                w = w[1:]
            while w and w[0].startswith("-") and head in ("nice", "env", "stdbuf", "sudo"):
                w = w[1:]
            continue
        break
    if not w:
        return "", [], via_bb
    return w[0].split("/")[-1], w[1:], via_bb


def expand(seg, depth=0):
    """Yield (segment, joined_by) including the inner command of sh -c / bash -c."""
    b, a, _ = base_and_args(seg)
    cflag = next((k for k, x in enumerate(a) if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", x)), None)
    if depth < 3 and b in ("sh", "bash", "dash", "ash", "zsh") and cflag is not None:
        i = cflag
        if i + 1 < len(a):
            for s, j in split_segments(a[i + 1]):
                yield from expand(s, depth + 1) if j != "|" else [(s, j)]
            return
    yield seg, ""


def session_segments(lines, leaves=None):
    """Flatten a session into ordered segments:
    [(idx, timestamp, segment_text, joined_by, base, args, via_busybox)].
    Parsing uses the submitted lines (quote-aware), because the sensor's own
    split on " && " / "; " ignores quotes. Each segment's timestamp is taken
    from the first sensor leaf at or after the previous match that contains its text (the
    sensor logs each chained part on completion); otherwise the line's own
    completion timestamp is used."""
    out = []
    leaves = list(leaves or [])
    ptr = 0
    for t_line, line in lines:
        for seg, joined in split_segments(line):
            t_s = t_line
            for k in range(ptr, min(ptr + 40, len(leaves))):
                if seg and seg in leaves[k][1] and leaves[k][0] <= t_line:
                    t_s, ptr = leaves[k][0], k
                    break
            parts = list(expand(seg))
            for k, (s, j) in enumerate(parts):
                b, a, bb = base_and_args(s)
                out.append((len(out), t_s, s, joined if k == 0 else (j or ";"), b, a, bb))
    return out


# ── 3. Classifiers ──────────────────────────────────────────────────────────
# Rule-defined recon: exactly the hunt.yml selection_recon + selection_sensitive_read.
HUNT_RECON_IMAGES = {"uname", "whoami", "id", "hostname", "w", "last", "lscpu", "ifconfig", "ip"}
HUNT_SENSITIVE = ("/etc/passwd", "/etc/shadow", "/etc/os-release", "/proc/cpuinfo")

# Broader host discovery (T1082/T1033/T1016/T1057 style), for the gap analysis only.
BROAD_RECON_IMAGES = HUNT_RECON_IMAGES | {
    "nproc", "free", "df", "lspci", "lsblk", "dmidecode", "arch", "getconf", "uptime",
    "ps", "top", "lsb_release", "hostnamectl", "who", "users", "groups", "netstat", "ss",
    "nvidia-smi", "lsusb", "dmesg", "env", "printenv", "crontab", "history", "locale",
}
BROAD_READ = re.compile(r"/proc/(cpuinfo|meminfo|version|mounts|self|\d+)|/etc/(passwd|shadow|group|os-release|issue|.*release|hostname|hosts|resolv\.conf|crontab)|/sys/class")
READERS = {"cat", "head", "tail", "grep", "egrep", "awk", "sed", "less", "more", "cut", "wc", "sort", "uniq", "ls"}

FETCH_TOOLS = {"wget", "curl", "tftp", "ftpget"}
URLISH = re.compile(r"(?i)(https?|ftp|tftp)://|^\d{1,3}(\.\d{1,3}){3}|[a-z0-9-]+\.[a-z]{2,}(/|:\d+|$)")


def is_hunt_recon(b, a):
    if b in HUNT_RECON_IMAGES:
        return True
    if b in ("cat", "head") and any(p in x for x in a for p in HUNT_SENSITIVE):
        return True
    return False


def is_broad_recon(b, a):
    if is_hunt_recon(b, a) or b in BROAD_RECON_IMAGES:
        return True
    if b in READERS and any(BROAD_READ.search(x) for x in a):
        return True
    return False


def is_fetch(b, a):
    """A download utility invoked with something that looks like a remote target."""
    if b not in FETCH_TOOLS:
        return False
    return any(URLISH.search(x) for x in a if not x.startswith("-")) or b == "tftp"


DELIVERY_PATTERNS = [
    ("base64_decode", re.compile(r"base64\s+(-d|--decode)|base64 -di|openssl\s+(base64|enc)\s+-d")),
    ("echo_hex_to_file", re.compile(r"(echo|printf)\s+(-[a-z]+\s+)*['\"]?(\\x[0-9a-fA-F]{2}){4,}.*>")),
    ("scp_sink", re.compile(r"^\s*scp\s+(-[a-zA-Z]+\s+)*-t\b")),
    ("dev_tcp", re.compile(r"/dev/(tcp|udp)/")),
    ("interpreter_net", re.compile(r"(python[23]?|perl|php|ruby)\s+.*(urllib|urlopen|requests\.get|LWP|IO::Socket|file_get_contents|Net::HTTP)")),
    ("nc_to_file", re.compile(r"\b(nc|ncat|netcat)\b[^|]*>\s*\S")),
    ("stdin_to_file", re.compile(r"\bcat\s*>{1,2}\s*[\"']?[^\s|;&<]+")),
]


def delivery_kinds(leaf_text):
    return [k for k, rx in DELIVERY_PATTERNS if rx.search(leaf_text)]


# ── 4. Pseudonyms and sanitising ────────────────────────────────────────────
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"(?i)\b(https?|ftp|tftp)://")
DOMAIN = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|me|tk|pw|in|su|br|de|us|uk|co|sh|site|online|club|link|live|space|pro|vip|app|dev))\b")


def defang(text, ipmap=None):
    """Defang URLs/domains/IPs. IPs become pseudonyms (dst-### for addresses
    inside commands) when ipmap is given, else are defanged with [.]."""
    text = URL.sub(lambda m: m.group(1).lower().replace("http", "hxxp").replace("ftp", "fxp") + "://", text)
    if ipmap is not None:
        text = IPV4.sub(lambda m: ipmap(m.group(0)), text)
    else:
        text = IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    text = DOMAIN.sub(lambda m: m.group(1).replace(".", "[.]"), text)
    return text


class Pseudo:
    """Stable pseudonyms. src-### for session source IPs, dst-### for IPs that
    appear inside commands. Numbered by first appearance in session order, so
    reruns on the same snapshot give the same labels."""

    def __init__(self, conn=None):
        self.src, self.dst = {}, {}
        if conn is not None:
            # Seed src-### over ALL sessions (operators included) in start order, so
            # labels match v1 even when operator sessions are excluded from analysis.
            for (ip,) in conn.execute("SELECT source_ip FROM sessions ORDER BY started_at, session_id"):
                self.s(ip)

    def s(self, ip):
        if ip not in self.src:
            self.src[ip] = "src-%03d" % (len(self.src) + 1)
        return self.src[ip]

    def d(self, ip):
        if ip in self.src:
            return self.src[ip]
        if ip not in self.dst:
            self.dst[ip] = "dst-%03d" % (len(self.dst) + 1)
        return self.dst[ip]

    def dump(self, path):
        with open(path, "w") as fh:
            fh.write("pseudonym,ip,kind\n")
            for ip, p in self.src.items():
                fh.write(f"{p},{ip},source\n")
            for ip, p in self.dst.items():
                fh.write(f"{p},{ip},in_command\n")


SECRETS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "<private-key-redacted>"),
    (re.compile(r"(?i)(echo\s+(?:-[a-z]+\s+)*)[^|;&]+?(\s*\|\s*sudo\s+-S\b)"), r"\1<redacted>\2"),
    (re.compile(r"(?i)(openssl\s+passwd\s+(?:-\S+\s+)*)[^\s)]+"), r"\1<redacted>"),
    (re.compile(r"(?i)(useradd\b[^;|&]*?\s-p\s+)(?!\$\()\S+"), r"\1<redacted>"),
    (re.compile(r"(__passwd_attempt__ user=\S+ (current|new)=).*"), r"\1<redacted>"),
    # echo <secret> | passwd / chpasswd  (covers "user:pass" and "pass\npass")
    (re.compile(r"(?i)(echo\s+(?:-[a-z]+\s+)*)[^|;&]+?(\s*\|\s*(?:sudo\s+)?(?:passwd|chpasswd)\b)"), r"\1<redacted>\2"),
    (re.compile(r"(?i)(chpasswd\s*<<<\s*)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)(sshpass\s+-p\s*)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)(curl\s[^|;]*?\s-u\s*)\S+"), r"\1<redacted>"),
    (re.compile(r"ssh-(rsa|ed25519|dss) [A-Za-z0-9+/=]{20,}"), r"ssh-\1 <key-redacted>"),
    (re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}"), "<long-base64-redacted>"),
    (re.compile(r"\b4[0-9AB][0-9a-zA-Z]{93}\b"), "<wallet-redacted>"),
]


def sanitize(text, pseudo):
    for rx, rep in SECRETS:
        text = rx.sub(rep, text)
    text = defang(text, pseudo.d)
    if len(text) > 300:
        text = text[:300] + " …[truncated]"
    return text


def load_sessions(conn, window_end=None, exclude=None):
    """Yield (session_id, source_ip, started_at, connection_type, [(ts, text)])
    in session start order. Operator sessions are skipped when EXCLUDE_OPERATORS
    (v2 default); sessions starting after window_end are skipped."""
    window_end = window_end or WINDOW_END
    exclude = excluded_ips() if exclude is None else exclude
    cur = conn.execute(
        "SELECT e.session_id, e.timestamp, json_extract(e.data,'$.command') "
        "FROM events e WHERE e.event_type='command' ORDER BY e.session_id, e.id")
    by = {}
    for sid, t_s, text in cur:
        by.setdefault(sid, []).append((t_s, text or ""))
    for sid, ip, st, ctype in conn.execute(
            "SELECT session_id, source_ip, started_at, connection_type FROM sessions "
            "WHERE started_at <= ? ORDER BY started_at, session_id", (window_end,)):
        if ip in exclude:
            continue
        yield sid, ip, st, ctype, by.get(sid, [])


# ── 5. Land-and-run (v2, Task C) ───────────────────────────────────────────
# Every rule below works on the quote-aware segments from session_segments().
# A "name" is the staged file's basename after normalisation (norm_name).
SHELL_KEYWORDS = {"then", "do", "else", "elif", "{", "!", "time"}
INTERPRETERS = {"sh", "bash", "dash", "ash", "zsh", "ksh", "busybox", "perl", "python", "python2", "python3", "php", "ruby", "node"}
SYSTEM_PREFIXES = ("/bin/", "/usr/", "/sbin/", "/lib", "/etc/", "/proc/", "/sys/", "/dev/")
CONFIG_TARGETS = re.compile(r"(authorized_keys|/etc/|sudoers|\.bashrc|\.profile|/dev/null|/dev/std|\.service$|\.timer$|crontab|/proc/)")
PERSIST_HINT = re.compile(r"crontab|@reboot|\*\s+\*\s+\*|ExecStart|systemctl|/etc/rc\.local|/etc/init\.d|\.service")


def clean_segment(seg):
    """Drop leading shell keywords and grouping characters: 'then cat > x' -> 'cat > x'."""
    s = seg.strip()
    while True:
        s2 = s.lstrip("({ ").strip()
        w = s2.split(None, 1)
        if w and w[0] in SHELL_KEYWORDS:
            s2 = w[1] if len(w) > 1 else ""
        if s2 == s:
            return s
        s = s2


def norm_name(p):
    """Normalise a path to the name used for stage/execute matching:
    strip quotes, trailing ';' ')' and '&', then take the basename. So
    './w.sh', '/tmp/w.sh', '"w.sh"', '~/.x/w.sh' all become 'w.sh'."""
    if not p:
        return ""
    p = p.strip().strip("'\"").rstrip(";)&").strip("'\"")
    if not p or p in ("-", ".", "..") or p.startswith("-"):
        return ""
    n = p.rstrip("/").split("/")[-1]
    return "" if n in (".", "..", "") else n


def _redirect_target(text):
    m = re.search(r"(?<![0-9&<])>{1,2}\s*([^\s|;&<>]+)", text)
    return m.group(1) if m else None


def _url_basename(args):
    for a in args:
        if re.match(r"(?i)^(https?|ftp|tftp)://", a) or (not a.startswith("-") and "/" in a and "." in a.split("/")[0]):
            return norm_name(a.split("?")[0])
    return ""


def fetch_to_file_name(b, args, text):
    """Name written by a fetch, or None if the fetch writes nowhere / to stdout."""
    if b == "wget":
        for i, a in enumerate(args):
            if a in ("-O", "--output-document") and i + 1 < len(args):
                return None if args[i + 1] == "-" else norm_name(args[i + 1])
            if a.startswith("-O") and len(a) > 2:
                return None if a[2:] == "-" else norm_name(a[2:])
            if re.match(r"^-[a-zA-Z]*O-$", a) or a.startswith("--output-document=-"):
                return None
            if re.match(r"^-[a-zA-Z]*O$", a) and i + 1 < len(args):  # -qO file
                return None if args[i + 1] == "-" else norm_name(args[i + 1])
        t = _redirect_target(text)
        return norm_name(t) if t else _url_basename(args)
    if b == "curl":
        for i, a in enumerate(args):
            if a in ("-o", "--output") and i + 1 < len(args):
                return norm_name(args[i + 1])
            if a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                return norm_name(a[2:])
            if a in ("-O", "--remote-name") or (re.match(r"^-[a-zA-Z]*O$", a)):
                return _url_basename(args)
        t = _redirect_target(text)
        return norm_name(t) if t else None
    if b == "tftp":
        for i, a in enumerate(args):
            if a in ("-r", "-l") and i + 1 < len(args):
                return norm_name(args[i + 1])
            if a == "get" and i + 1 < len(args):
                return norm_name(args[i + 1])
        return None
    if b == "ftpget":
        pos = [a for a in args if not a.startswith("-")]
        return norm_name(pos[1]) if len(pos) >= 2 else None
    return None


def land_run_events(lines, leaves=None):
    """Return [(idx, ts, kind, method, name, text)] for one session.
    kind: stage | inmem | exec | exec_persist | execlike | config
    Rules (see land_and_run.md for the prose version):
      stage/fetch_to_file   wget/curl/tftp/ftpget (also via busybox) that writes a file,
                            not piped onward
      stage/stdin_to_file   cat > f  (no input file)
      stage/scp_sink        scp -t <path>  (the receiving end of a push into the host)
      stage/scp_pull        scp [opts] user@host:remote <local>  (host pulls a file)
      stage/echo_to_file    echo|printf ... > f   (config targets excluded)
      stage/base64_to_file  base64 -d ... > f
      stage/dev_tcp_to_file a /dev/tcp read redirected to a file
      stage/rename          mv|cp <staged> <new>: new name is linked to the staged one
      inmem                 fetch or base64 decode piped into an interpreter;
                            sh|bash -c "$(curl|wget ...)"; eval "$(curl ...)"
      exec/path             ./x, /tmp/x, ~/x ... (non-system path) as the command
      exec/interpreter      sh|bash|perl|python <file> (not -c / -e / -s)
      exec/source           . x | source x
      exec_persist          a cron / systemd / rc line that contains the name
      execlike              interpreter one-liners (python -c, perl -e, php -r),
                            /dev/tcp reverse shells, nc -e, system binaries run by path
      config                echo/cat writes to authorized_keys, sudoers, /etc/...
      probe                 echo/printf of a short literal (<= 16 chars, no \\x escapes,
                            no command substitution) to a file: a writability test
      inmem/interpreter_reads_stdin  sh|bash|perl|python < /dev/stdin, or 'sh -s' alone
      execlike additions    python -m, VAR=$(...) assignments skipped, './' or '/' with no
                            name, root-level single tokens such as RouterOS '/ip', and
                            '. /etc/...' sourcing of system files
    """
    segs = session_segments(lines, leaves)
    out = []
    staged_names = set()
    for k, (i, t_s, text, joined, b0, a0, bb) in enumerate(segs):
        seg = clean_segment(text)
        b, a, bb = base_and_args(seg)
        nxt = segs[k + 1] if k + 1 < len(segs) else None
        piped_on = nxt is not None and nxt[3] == "|"
        nxt_base = base_and_args(clean_segment(nxt[2]))[0] if nxt else ""
        full = seg
        # in-memory
        if (b in FETCH_TOOLS or (b == "base64" and any(x in ("-d", "--decode", "-di") for x in a))) and piped_on and nxt_base in INTERPRETERS:
            out.append((i, t_s, "inmem", f"{b}_pipe_{nxt_base}", "", text)); continue
        if re.search(r"\b(sh|bash|dash|ash)\s+-c\s+[\"']?(\$\(|`)\s*(curl|wget)\b|\beval\s+[\"']?\$\(\s*(curl|wget)\b", full):
            out.append((i, t_s, "inmem", "shell_c_substitution", "", text)); continue
        # stage: fetch to file
        if b in FETCH_TOOLS or b == "ftpget":
            if piped_on:
                continue
            name = fetch_to_file_name(b, a, seg)
            if name and not CONFIG_TARGETS.search(seg.split(">")[-1] if ">" in seg else " ".join(a)):
                out.append((i, t_s, "stage", "fetch_to_file", name, text)); staged_names.add(name)
            elif name:
                out.append((i, t_s, "config", "fetch_to_config", name, text))
            continue
        tgt = _redirect_target(seg)
        if b == "cat" and tgt and not [x for x in a if not x.startswith((">", "-", "<")) and norm_name(x) != norm_name(tgt)]:
            kind = "config" if CONFIG_TARGETS.search(tgt) else "stage"
            out.append((i, t_s, kind, "stdin_to_file", norm_name(tgt), text))
            if kind == "stage":
                staged_names.add(norm_name(tgt))
            continue
        if b == "scp" and "-t" not in a and "-f" not in a:
            pos = [x for x in a if not x.startswith("-")]
            # drop option values of -F/-i/-P/-o
            opts_with_val = {"-F", "-i", "-P", "-o", "-c", "-l", "-S", "-J"}
            pos, skip = [], False
            for x in a:
                if skip:
                    skip = False; continue
                if x in opts_with_val:
                    skip = True; continue
                if not x.startswith("-"):
                    pos.append(x)
            if len(pos) >= 2 and re.match(r"^[^/\s]*:", pos[0]) and not re.match(r"^[^/\s]*:", pos[-1]):
                name = norm_name(pos[-1])
                out.append((i, t_s, "stage", "scp_pull", name, text)); staged_names.add(name)
            continue
        if b == "scp" and "-t" in a:
            name = norm_name(next((x for x in reversed(a) if not x.startswith("-")), ""))
            out.append((i, t_s, "stage", "scp_sink", name, text)); staged_names.add(name); continue
        if b == "base64" and tgt and any(x in ("-d", "--decode", "-di") for x in a):
            out.append((i, t_s, "stage", "base64_to_file", norm_name(tgt), text)); staged_names.add(norm_name(tgt)); continue
        if "/dev/tcp/" in seg and tgt and not re.search(r">&\s*/dev/tcp|>\s*/dev/tcp", seg):
            out.append((i, t_s, "stage", "dev_tcp_to_file", norm_name(tgt), text)); staged_names.add(norm_name(tgt)); continue
        if b in ("echo", "printf") and tgt:
            body = seg.split(">")[0]
            payload = " ".join(x for x in a if not x.startswith("-") and ">" not in x and x != tgt)
            if PERSIST_HINT.search(seg):
                pass  # handled as exec_persist below
            elif len(payload) <= 16 and "\\x" not in body and "$(" not in body and "`" not in body and "\n" not in payload:
                out.append((i, t_s, "probe", "write_probe", norm_name(tgt), text)); continue
            else:
                kind = "config" if CONFIG_TARGETS.search(tgt) else "stage"
                out.append((i, t_s, kind, "echo_to_file", norm_name(tgt), text))
                if kind == "stage":
                    staged_names.add(norm_name(tgt))
                continue
        if b in ("mv", "cp"):
            pos = [x for x in a if not x.startswith("-")]
            if len(pos) >= 2 and norm_name(pos[0]) in staged_names:
                out.append((i, t_s, "stage", "rename", norm_name(pos[-1]), text)); staged_names.add(norm_name(pos[-1]))
            continue
        # persistence reference (cron / systemd / rc)
        if PERSIST_HINT.search(text):
            names = {n for n in staged_names if n and re.search(r"(^|[/\s\"'])" + re.escape(n) + r"($|[\s\"';&])", text)}
            for n in names:
                out.append((i, t_s, "exec_persist", "cron_or_unit_reference", n, text))
            if names:
                continue
        if b in ("sh", "bash", "dash", "ash", "perl", "python", "python3") and re.search(r"<\s*/dev/stdin|^\S+\s+-s\s*$", seg) and joined != "|":
            out.append((i, t_s, "inmem", "interpreter_reads_stdin", "", text)); continue
        # execute-like, nothing new
        if (b in ("python", "python2", "python3") and ("-c" in a or "-m" in a)) or (b == "perl" and "-e" in a) or (b == "php" and "-r" in a) \
                or re.search(r">&\s*/dev/tcp|/dev/tcp/.*0>&1|\bnc\b.*\s-e\s", seg) or (b in ("bash", "sh") and "-i" in a):
            out.append((i, t_s, "execlike", "interpreter_or_reverse_shell", "", text)); continue
        # execute: path invocation
        head = words(seg)
        if head and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*(\$\(|`)", head[0]):
            continue  # VAR=$(...) assignment: the substituted command is not a staged file
        head = [w for w in head if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w)]
        while head and head[0].split("/")[-1] in WRAPPERS:
            head = head[1:]
        kept, skip = [], False
        for w in head:  # drop redirections, including the target of a bare '>' / '<'
            if skip:
                skip = False; continue
            if re.match(r"^\d*[<>]+&?$", w):
                skip = True; continue
            if re.match(r"^\d*[<>]", w):
                continue
            kept.append(w)
        head = kept
        cmd0 = head[0] if head else ""
        if "/" in cmd0 and not cmd0.startswith("-"):
            nm = norm_name(cmd0)
            if cmd0.startswith(SYSTEM_PREFIXES) or not nm:
                out.append((i, t_s, "execlike", "system_binary_or_empty_path", nm, text))
            elif re.match(r"^/[a-z-]+$", cmd0):
                out.append((i, t_s, "execlike", "root_level_token_eg_routeros", nm, text))
            else:
                out.append((i, t_s, "exec", "path", nm, text))
            continue
        if b in ("sh", "bash", "dash", "ash", "perl", "python", "python2", "python3") and not piped_on and joined != "|":
            if any(re.match(r"^-[a-zA-Z]*[ces][a-zA-Z]*$", x) for x in a):
                continue  # -c / -e / -s, also combined forms such as -lc
            files = [x for x in a if not x.startswith("-") and not re.match(r"^\d*[<>&]", x)]
            if files:
                out.append((i, t_s, "exec", "interpreter_file", norm_name(files[0]), text))
            continue
        if cmd0 in (".", "source") and len(head) > 1:
            if head[1].startswith(SYSTEM_PREFIXES):
                out.append((i, t_s, "execlike", "source_system_file", norm_name(head[1]), text))
            else:
                out.append((i, t_s, "exec", "source", norm_name(head[1]), text))
    return out
