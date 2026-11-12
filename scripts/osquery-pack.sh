#!/usr/bin/env bash
# Create or update the osquery pack in Kibana from osquery/lab-persistence-pack.json.
# Run on the siem VM:  sudo bash /vagrant/scripts/osquery-pack.sh [default_seconds] [query_name=seconds ...]
#   default_seconds   : set every query's interval (omit to keep the file's per-query values)
#   query_name=seconds: override one query's interval, e.g.  startup_items=300 services=600
#   examples:  osquery-pack.sh                 (file defaults, hourly)
#              osquery-pack.sh 300             (all queries every 5 min)
#              osquery-pack.sh 3600 services=300 scheduled_tasks=300  (hourly, but those two every 5 min)
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
KB="https://localhost:5601"
kb() { curl -sS --fail-with-body --cacert /opt/elk/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
         -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' -H 'Content-Type: application/json' "$@"; }
default=""; overrides='{}'
for a in "$@"; do
  if [[ "$a" == *=* ]]; then overrides=$(jq --arg k "${a%%=*}" --argjson v "${a#*=}" '. + {($k):$v}' <<<"$overrides")
  else default="$a"; fi
done
body=$(jq --arg d "$default" --argjson ov "$overrides" '
  (if $d == "" then . else .queries |= map_values(.interval = ($d | tonumber)) end)
  | reduce ($ov | to_entries[]) as $e (.; if .queries[$e.key] then .queries[$e.key].interval = $e.value else . end)' \
  /vagrant/osquery/lab-persistence-pack.json)
name=$(jq -r .name <<<"$body")
id=$(kb "$KB/api/osquery/packs?pageSize=100" | jq -r --arg n "$name" '[.data[]? | select(.name == $n)][0].saved_object_id // [.data[]? | select(.name == $n)][0].id // empty')
if [ -n "$id" ]; then
  kb -X PUT "$KB/api/osquery/packs/$id" -d "$body" | jq -c '{updated: .data.name, queries: (.data.queries | length)}'
else
  kb -X POST "$KB/api/osquery/packs" -d "$body" | jq -c '{created: .data.name, queries: (.data.queries | length)}'
fi
