#!/usr/bin/env bash
# Checks the linter against a real Asterisk. It starts Asterisk on the fixture
# configurations and verifies that what the rules claim is true:
#
#   good/  everything loads, AMI listens on loopback only, its ACL keeps other
#          addresses out, and the linter finds nothing.
#   bad/   AMI really listens on 0.0.0.0, a "permit" without "deny" really lets
#          every address in, the HTTP server really listens publicly, and the
#          lines the linter calls unreadable are the ones Asterisk complains about.
#
# Needs the Asterisk packages of the distribution (apt install asterisk), python3,
# and a built linter (go build -o asterisk-conf-lint ./cmd/asterisk-conf-lint).
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
lint=${LINT:-$root/asterisk-conf-lint}
work=$(mktemp -d)
failed=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; failed=1; }
expect() { # expect "description" command...
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi
}

command -v asterisk >/dev/null || { echo "asterisk is not installed" >&2; exit 2; }
[ -x "$lint" ] || { echo "build the linter first: $lint not found" >&2; exit 2; }
sudo systemctl stop asterisk 2>/dev/null || true

moddir=$(dirname "$(find /usr/lib /usr/lib64 -name app_dial.so -print -quit)")
echo "Asterisk $(asterisk -V), modules in $moddir"

start() { # start NAME OVERLAY-DIR [FILE-TO-REMOVE...]
  local name=$1 overlay=$2
  shift 2
  dir=$work/$name
  mkdir -p "$dir"/{var,spool,run,log,agi}
  cp -r /etc/asterisk "$dir/etc"
  cp -r "$overlay"/. "$dir/etc/"
  for f in "$@"; do rm -f "$dir/etc/$f"; done
  cat >"$dir/etc/asterisk.conf.tmp" <<CONF
[directories]
astetcdir => $dir/etc
astmoddir => $moddir
astvarlibdir => /var/lib/asterisk
astdbdir => $dir/var
astkeydir => $dir/var
astdatadir => /usr/share/asterisk
astagidir => $dir/agi
astspooldir => $dir/spool
astrundir => $dir/run
astlogdir => $dir/log
CONF
  # keep the fixture's own [options] (runuser, execincludes), add our directories
  if [ -f "$overlay/asterisk.conf" ]; then
    cat "$overlay/asterisk.conf" >>"$dir/etc/asterisk.conf.tmp"
  fi
  mv "$dir/etc/asterisk.conf.tmp" "$dir/etc/asterisk.conf"
  # The fixtures name a runuser we do not have here; run as the current user.
  sed -i '/^runuser\|^rungroup/d' "$dir/etc/asterisk.conf"
  printf '[logfiles]\nfull => notice,warning,error\n' >"$dir/etc/logger.conf"
  asterisk -C "$dir/etc/asterisk.conf" >"$dir/start.out" 2>&1
  for _ in $(seq 1 60); do
    asterisk -C "$dir/etc/asterisk.conf" -rx 'core waitfullybooted' 2>/dev/null | grep -q 'fully booted' && return 0
    sleep 1
  done
  cat "$dir/start.out" "$dir/log/full" 2>/dev/null | tail -20
  return 1
}
cli() { asterisk -C "$dir/etc/asterisk.conf" -rx "$1" 2>&1; }
stop() { asterisk -C "$dir/etc/asterisk.conf" -rx 'core stop now' >/dev/null 2>&1; sleep 2; }
listeners() { python3 "$root/hack/listeners.py" "$1"; }

# ---------------------------------------------------------------- good/
echo "== good configuration"
start good "$root/testdata/good" sip.conf || { bad "Asterisk did not start on the good configuration"; exit 1; }
expect "pjsip endpoint 101 is loaded" bash -c "$(declare -f cli); dir=$dir; cli 'pjsip show endpoints' | grep -q '101'"
expect "pjsip endpoint provider is loaded" bash -c "$(declare -f cli); dir=$dir; cli 'pjsip show endpoints' | grep -q 'provider'"
if [ "$(listeners 5038)" = "127.0.0.1:5038" ]; then ok "AMI listens on 127.0.0.1 only"; else bad "AMI listeners: $(listeners 5038)"; fi
if [ "$(listeners 8088)" = "127.0.0.1:8088" ]; then ok "HTTP listens on 127.0.0.1 only"; else bad "HTTP listeners: $(listeners 8088)"; fi
[ "$(python3 "$root/hack/ami_login.py" monitor Zq7xR2mV9pLw4TnC8dYe3Ka 127.0.0.1)" = accepted ] && ok "AMI user monitor logs in from 127.0.0.1" || bad "monitor from 127.0.0.1"
[ "$(python3 "$root/hack/ami_login.py" monitor Zq7xR2mV9pLw4TnC8dYe3Ka 127.0.0.2)" = rejected ] && ok "the ACL keeps 127.0.0.2 out" || bad "monitor from 127.0.0.2 should be rejected"
[ "$(python3 "$root/hack/ami_login.py" monitor wrong-secret 127.0.0.1)" = rejected ] && ok "a wrong secret is rejected" || bad "wrong secret accepted"

# What Asterisk complains about while loading, and what the linter says.
agree() { # agree DIR: every unreadable line Asterisk names must be a CFG-000 finding
  local d=$1 log=$1/log/full missing=0
  grep -oE 'line [0-9]+ of [^ ]+' "$log" | sort -u | while read -r _ n _ file; do
    printf '%s:%s\n' "$(basename "$file")" "$n"
  done >"$d/asterisk-lines.txt"
  "$lint" -format json -fail-on none "$d/etc" | python3 "$root/hack/lint_lines.py" | sort -u >"$d/linter-lines.txt"
  while read -r line; do
    grep -qx "$line" "$d/linter-lines.txt" || { echo "Asterisk rejects $line, the linter does not"; missing=1; }
  done <"$d/asterisk-lines.txt"
  return $missing
}
if agree "$dir"; then ok "every line Asterisk rejects is reported as CFG-000 ($(wc -l <"$dir/asterisk-lines.txt") of them)"; else bad "linter misses lines Asterisk rejects"; fi

out=$("$lint" -no-color "$dir/etc")
echo "$out" | grep -v '^    fix' | sed 's/^/      /'
# The stock files that ship with Asterisk are not ours to fix; only the known
# sample-file wart (geolocation.conf) and nothing else may show up.
unexpected=$(echo "$out" | grep -E '^/.*  (low|medium|high|critical)' | grep -v 'geolocation.conf' || true)
if [ -z "$unexpected" ]; then ok "the linter finds nothing in the good configuration"; else bad "unexpected findings: $unexpected"; fi
stop

# ---------------------------------------------------------------- bad/
echo "== bad configuration"
start bad "$root/testdata/bad" || { bad "Asterisk did not start on the bad configuration"; exit 1; }
[ "$(listeners 5038)" = "0.0.0.0:5038" ] && ok "AMI-001: AMI really listens on 0.0.0.0" || bad "AMI listeners: $(listeners 5038)"
[ "$(listeners 8088)" = "0.0.0.0:8088" ] && ok "HTTP-001: the HTTP server really listens on 0.0.0.0" || bad "HTTP listeners: $(listeners 8088)"
[ "$(python3 "$root/hack/ami_login.py" admin admin 127.0.0.1)" = accepted ] && ok "AMI-002/003: admin/admin logs in" || bad "admin/admin was rejected"
[ "$(python3 "$root/hack/ami_login.py" reports Xk9vQ3pLm7Rt2WzHb5 127.0.0.2)" = accepted ] \
  && ok "AMI-002: permit 10.0.0.0/8 without a deny does not keep 127.0.0.2 out" || bad "reports from 127.0.0.2 was rejected"
expect "PJS-001: the anonymous endpoint exists" bash -c "$(declare -f cli); dir=$dir; cli 'pjsip show endpoints' | grep -q 'anonymous'"
expect "SIP-001: chan_sip allows unknown (guest) callers" bash -c "$(declare -f cli); dir=$dir; cli 'sip show settings' | grep -i 'allow unknown access' | grep -qi 'yes'"
if agree "$dir"; then ok "every line Asterisk rejects is reported as CFG-000 ($(wc -l <"$dir/asterisk-lines.txt") of them)"; else bad "linter misses lines Asterisk rejects"; fi
stop

rm -rf "$work"
exit $failed
