#!/usr/bin/env bash
# Fails when a test binds a hard-coded port. Tests get ports at run time from
# tests/iora_test_net_utils.hpp (getFreePortTCP / getFreePortUDP /
# getFreePortUdpTcp) or from a listener bound to port 0 (makeListener,
# bindLoopbackV4Ephemeral). Lines that match a pattern but bind nothing are
# listed in fixed_port_allowlist.txt with the reason.
#
# Usage: check_no_fixed_ports.sh <tests-dir>
set -u

dir="${1:-.}"
allowlist="$dir/fixed_port_allowlist.txt"
if [ ! -d "$dir" ] || [ ! -f "$allowlist" ]; then
  echo "check_no_fixed_ports: no tests dir or allowlist at: $dir"
  exit 2
fi

patterns=(
  '(?i)\b\w*port\w*\s*(=|\{|\()\s*[0-9]{2,5}\b'
  'setPort\(\s*[0-9]'
  '\.start\(\s*[0-9]{2,5}'
  'Fixture\w*\s+\w+\(\s*[0-9]{2,5}\s*\)'
  '(127\.0\.0\.1|localhost|\[::1\]):[0-9]{2,5}\b'
  '\b(findAvailablePort|isPortAvailable|pickPort|g_nextPort|nextPort)\b'
  'getFreePort(TCP|UDP)?\(\s*[0-9]'
  '(?i)\b\w*port\w*\)?\s*\+\s*[0-9]'
  '"(127\.0\.0\.1|0\.0\.0\.0|localhost|::1)"\s*,\s*[0-9]{2,5}\b'
)

hits=""
for p in "${patterns[@]}"; do
  out=$(cd "$dir" && grep -rnP --include='*.cpp' --include='*.hpp' -- "$p" .)
  status=$?
  if [ "$status" -ge 2 ]; then
    echo "check_no_fixed_ports: grep failed (status $status) for pattern: $p"
    exit 2
  fi
  out=$(printf '%s\n' "$out" | grep -vP '^[^:]+:[0-9]+:\s*//')
  if [ -n "$out" ]; then
    hits+="$out"$'\n'
  fi
done

fail=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  rest="${line#*:}"
  text="${rest#*:}"
  allowed=0
  while IFS='|' read -r afile afrag areason; do
    [ -z "$afile" ] && continue
    case "$afile" in \#*) continue ;; esac
    if [ "./$afile" = "$file" ] && [[ "$text" == *"$afrag"* ]]; then
      allowed=1
      break
    fi
  done < "$allowlist"
  if [ "$allowed" -eq 0 ]; then
    echo "fixed port: $line"
    fail=1
  fi
done < <(printf '%s' "$hits" | sort -u)

if [ "$fail" -ne 0 ]; then
  echo "Use testnet::getFreePortTCP()/getFreePortUDP()/getFreePortUdpTcp() or a port-0 listener;"
  echo "if the line binds nothing, add it to tests/fixed_port_allowlist.txt with the reason."
  exit 1
fi
exit 0
