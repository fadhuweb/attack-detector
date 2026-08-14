#!/usr/bin/env bash
# Day 1 verification. RUN THIS ON THE TARGET (192.168.50.10), not on Windows.
#
#   ./scripts/verify_day1.sh          checks + admin address discovery
#   ./scripts/verify_day1.sh --live   watch for real failed-password lines
#
# Day 1 is not closed until this passes here. The rename-rotation case cannot
# run on Windows, so until it runs on Linux the tailer every detector sits on
# has no real coverage for the moment logs rotate.

set -uo pipefail
cd "$(dirname "$0")/.."

PY=./.venv/bin/python
[[ -x "$PY" ]] || PY=python3

fail=0
hr() { printf '%s\n' "----------------------------------------------------------"; }

if [[ "${1:-}" == "--live" ]]; then
  out=$(mktemp)
  echo "Watching /var/log/auth.log for 60s."
  echo "From the attacker box (192.168.50.11), run this and give a wrong password 3+ times:"
  echo
  echo "    ssh baduser@192.168.50.10"
  echo
  hr
  timeout 60 "$PY" -m attack_detector.engine | tee "$out"
  hr
  seen=$(grep -c 'ssh_failed_login' "$out" 2>/dev/null || true)
  ips=$(grep -o 'src=[0-9.]*' "$out" 2>/dev/null | sort -u | tr '\n' ' ')
  rm -f "$out"
  if [[ "${seen:-0}" -gt 0 ]]; then
    echo "PASS: saw $seen ssh_failed_login event(s) from: ${ips:-none}"
  else
    echo "FAIL: no ssh_failed_login events seen."
    echo "  - Did the wrong-password SSH actually run during the 60s window?"
    echo "  - Check the raw log directly:  sudo tail -f /var/log/auth.log"
    exit 1
  fi
  exit 0
fi

hr
echo "1/4  auth log source"
if [[ ! -e /var/log/auth.log ]]; then
  echo "  FAIL /var/log/auth.log does not exist (no rsyslog?)."
  echo "       sudo apt-get install -y rsyslog && sudo systemctl enable --now rsyslog"
  echo "       or set sources.auth.type: journald in config.yaml"
  fail=1
elif [[ ! -r /var/log/auth.log ]]; then
  echo "  FAIL /var/log/auth.log exists but is not readable as $(whoami)."
  echo "       sudo usermod -aG adm $(whoami)   then log out and back in"
  fail=1
else
  echo "  ok   readable as $(whoami) ($(wc -l < /var/log/auth.log) lines)"
fi

hr
echo "2/4  parser tests"
"$PY" -m tests.test_auth_parser || fail=1

hr
echo "3/4  tailer rotation tests   <-- the rename case only runs here"
"$PY" -m tests.test_tailer_rotation || fail=1

hr
echo "4/4  admin allowlist candidates"
echo "  The address the target sees your admin session on. Put this in"
echo "  config.yaml under admin_allowlist. It is NOT your Windows IP if you"
echo "  connect through a NAT port-forward."
echo
if [[ -n "${SSH_CLIENT:-}" ]]; then
  echo "    SSH_CLIENT (this session):  $(echo "$SSH_CLIENT" | awk '{print $1}')"
fi
who_out=$(who 2>/dev/null | sed -n 's/.*(\(.*\)).*/    who:                        \1/p' | sort -u)
[[ -n "$who_out" ]] && echo "$who_out"
ss_out=$(ss -tn 2>/dev/null | awk '$1=="ESTAB" && $4 ~ /:22$/ {sub(/:[0-9]+$/,"",$5); print "    ss (established on :22):    " $5}' | sort -u)
[[ -n "$ss_out" ]] && echo "$ss_out"
echo
echo "  Never allowlist 192.168.50.11 (the attacker box)."

hr
if [[ "$fail" -ne 0 ]]; then
  echo "DAY 1 NOT CLOSED: fix the failures above."
  exit 1
fi
echo "Checks passed. Now confirm real traffic:  ./scripts/verify_day1.sh --live"
