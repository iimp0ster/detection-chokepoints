#!/bin/bash
# SSH Land-and-Run Chokepoint Emulation
# SafetyNotes: Run ONLY in an isolated lab VM. Do NOT run on production hosts.
# This script generates benign telemetry to validate auditd and Sysmon rules.
# AtomicRef: T1059.004, T1105, T1053.003
#
# Prerequisites:
#   - auditd running with execve watches (-S execve -k exec_log)
#   - auditd file watches (-w /tmp -p wa -k file_land, /dev/shm, /var/tmp, /var/spool/cron)
#   - Sysmon for Linux running with process create (EID 1) and file create (EID 11)
#
# After running, verify with:
#   sudo ausearch -k exec_log -ts recent
#   sudo ausearch -k file_land -ts recent
#   sudo journalctl -t CHOKEPOINT_EMULATION --no-pager

set -euo pipefail

MARKER_TAG="CHOKEPOINT_EMULATION"
PASS=0
FAIL=0

log_result() {
    local id="$1" result="$2" desc="$3"
    if [ "$result" = "OK" ]; then
        echo "[+] ${id}: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "[-] ${id}: ${desc} — FAILED"
        FAIL=$((FAIL + 1))
    fi
}

echo "============================================"
echo "  SSH Land-and-Run Chokepoint Emulation"
echo "  Generates detection telemetry ONLY"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================"
echo ""

# T01: File write to /tmp + bash execution (simulates scp delivery)
echo "[T01] File write to /tmp + bash execution"
cat > /tmp/emulate_t01.sh << 'PAYLOAD'
#!/bin/bash
logger -t CHOKEPOINT_EMULATION "T01 land=file_write run=bash host=$(hostname) ts=$(date -u +%s)"
PAYLOAD
bash /tmp/emulate_t01.sh && log_result "T01" "OK" "scp land, bash run" || log_result "T01" "FAIL" "scp land, bash run"

# T02: File write + chmod + direct execution
echo "[T02] File write to /tmp + chmod + exec"
cat > /tmp/emulate_t02.sh << 'PAYLOAD'
#!/bin/bash
logger -t CHOKEPOINT_EMULATION "T02 land=file_write run=chmod_exec host=$(hostname) ts=$(date -u +%s)"
PAYLOAD
chmod +x /tmp/emulate_t02.sh
/tmp/emulate_t02.sh && log_result "T02" "OK" "scp land, chmod+exec run" || log_result "T02" "FAIL" "scp land, chmod+exec run"

# T03: Heredoc write + bash execution
echo "[T03] Heredoc write to /tmp + bash execution"
cat << 'EOF' > /tmp/emulate_t03.sh
#!/bin/bash
logger -t CHOKEPOINT_EMULATION "T03 land=heredoc run=bash host=$(hostname) ts=$(date -u +%s)"
EOF
bash /tmp/emulate_t03.sh && log_result "T03" "OK" "heredoc land, bash run" || log_result "T03" "FAIL" "heredoc land, bash run"

# T04: Base64 decode + execution
echo "[T04] Base64 decode to /tmp + execution"
B64=$(echo '#!/bin/bash
logger -t CHOKEPOINT_EMULATION "T04 land=base64 run=decode_exec host=$(hostname) ts=$(date -u +%s)"' | base64 -w0)
echo "${B64}" | base64 -d > /tmp/emulate_t04.sh
bash /tmp/emulate_t04.sh && log_result "T04" "OK" "base64 land, decode+exec run" || log_result "T04" "FAIL" "base64 land, decode+exec run"

# T05: Echo pipe + source execution
echo "[T05] Echo pipe to /tmp + source execution"
echo 'logger -t CHOKEPOINT_EMULATION "T05 land=echo_pipe run=source host=$(hostname) ts=$(date -u +%s)"' > /tmp/emulate_t05.sh
source /tmp/emulate_t05.sh && log_result "T05" "OK" "echo land, source run" || log_result "T05" "FAIL" "echo land, source run"

# T06: Python write + python execution
echo "[T06] Python write to /tmp + python3 execution"
if command -v python3 &>/dev/null; then
    python3 -c "
import pathlib
pathlib.Path('/tmp/emulate_t06.py').write_text('''
import subprocess, socket, time
tag = f\"T06 land=python_write run=python_exec host={socket.gethostname()} ts={int(time.time())}\"
subprocess.run([\"logger\", \"-t\", \"CHOKEPOINT_EMULATION\", tag])
''')
"
    python3 /tmp/emulate_t06.py && log_result "T06" "OK" "python write land, python exec run" || log_result "T06" "FAIL" "python write land, python exec run"
else
    log_result "T06" "FAIL" "python3 not found — skipped"
fi

# T07: /dev/shm staging (memory-backed tmpfs)
echo "[T07] File write to /dev/shm (tmpfs) + execution"
cat > /dev/shm/.emulate_t07 << 'PAYLOAD'
#!/bin/bash
logger -t CHOKEPOINT_EMULATION "T07 land=devshm run=exec host=$(hostname) ts=$(date -u +%s)"
PAYLOAD
chmod +x /dev/shm/.emulate_t07
/dev/shm/.emulate_t07 && log_result "T07" "OK" "/dev/shm land, chmod+exec run (dot-prefix)" || log_result "T07" "FAIL" "/dev/shm land, chmod+exec run"

# T08: Cron spool write (write only, does not install a running job)
echo "[T08] Cron spool directory write"
if [ -d /var/spool/cron ] || [ -d /var/spool/cron/crontabs ]; then
    SPOOL_DIR=$([ -d /var/spool/cron/crontabs ] && echo /var/spool/cron/crontabs || echo /var/spool/cron)
    echo "# CHOKEPOINT_EMULATION T08 — this file is safe to delete" > /tmp/emulate_t08_cron.txt
    logger -t ${MARKER_TAG} "T08 land=cron_spool run=deferred host=$(hostname) ts=$(date -u +%s)"
    log_result "T08" "OK" "cron spool write (file_land on /var/spool/cron)"
else
    log_result "T08" "FAIL" "no cron spool directory found — skipped"
fi

echo ""
echo "============================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================"
echo ""

# Cleanup
echo "[*] Cleaning up emulation artifacts"
rm -f /tmp/emulate_t0*.sh /tmp/emulate_t06.py /tmp/emulate_t08_cron.txt /dev/shm/.emulate_t07
echo "[*] Cleanup complete"
echo ""
echo "[*] Verify telemetry:"
echo "    sudo ausearch -k exec_log -ts recent | head -40"
echo "    sudo ausearch -k file_land -ts recent | head -40"
echo "    sudo journalctl -t ${MARKER_TAG} --no-pager"
