#!/usr/bin/env bash
# Create or update the osquery pack in Kibana from osquery/lab-persistence-pack.json.
# Run on the siem VM:  sudo bash /vagrant/scripts/osquery-pack.sh [interval_seconds]
#   interval_seconds overrides every query interval (e.g. 300 while testing; default: as in the file)
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
KB="https://localhost:5601"
kb() { curl -sS --fail-with-body --cacert /opt/elk/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
         -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' -H 'Content-Type: application/json' "$@"; }
body=$(jq --arg i "${1:-}" 'if $i == "" then . else .queries |= map_values(.interval = ($i | tonumber)) end' \
        /vagrant/osquery/lab-persistence-pack.json)
name=$(jq -r .name <<<"$body")
id=$(kb "$KB/api/osquery/packs?pageSize=100" | jq -r --arg n "$name" '[.data[]? | select(.name == $n)][0].saved_object_id // [.data[]? | select(.name == $n)][0].id // empty')
if [ -n "$id" ]; then
  kb -X PUT "$KB/api/osquery/packs/$id" -d "$body" | jq -c '{updated: .data.name, queries: (.data.queries | length)}'
else
  kb -X POST "$KB/api/osquery/packs" -d "$body" | jq -c '{created: .data.name, queries: (.data.queries | length)}'
fi
