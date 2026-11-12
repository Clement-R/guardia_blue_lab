#!/usr/bin/env bash
# On-demand YARA scan of the DC via an osquery LIVE query (not scheduled).
# Run on the siem VM:
#   sudo bash /vagrant/scripts/osquery-yara.sh [path-glob ...]
# With no args it scans the user-writable dirs; pass one or more Windows path globs to override, e.g.
#   sudo bash /vagrant/scripts/osquery-yara.sh 'C:\Users\%%' 'C:\Temp\%%'
# Results (matches) land in logs-osquery_manager.result-* and trigger the "osquery: YARA match" rule.
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
KB="https://localhost:5601"; AGENT="dc01"
RULES='C:\ProgramData\yara\yara-forge-core.yar'
kb() { curl -sS --fail-with-body --cacert /opt/elk/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
         -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' -H 'Content-Type: application/json' "$@"; }

paths=("$@"); [ ${#paths[@]} -eq 0 ] && paths=('C:\Users\%%' 'C:\Windows\Temp\%%' 'C:\PerfLogs\%%' 'C:\ProgramData\%%')
where=""; for p in "${paths[@]}"; do where+="path LIKE '${p}' OR "; done; where="(${where% OR })"
sql="SELECT path, matches, count, strings, tags FROM yara WHERE ${where} AND sigfile = '${RULES}' AND count > 0;"

aid=$(kb "$KB/api/fleet/agents?kuery=local_metadata.host.hostname:${AGENT}" | jq -r '.items[0].id // empty')
[ -n "$aid" ] || { echo "agent $AGENT not found/online" >&2; exit 1; }

body=$(jq -n --arg a "$aid" --arg q "$sql" '{agent_ids:[$a], query:$q}')
resp=$(kb -X POST "$KB/api/osquery/live_queries" -d "$body")
aid2=$(jq -r '.data.action_id // .data.actionId // empty' <<<"$resp")
echo "live YARA scan launched on ${AGENT} (action ${aid2:-?}); scanning: ${paths[*]}"
echo "Results in a few seconds: Kibana > Osquery > results, or Discover (logs-osquery_manager.result-*) filtered on action_data.id:\"${aid2}\"."
