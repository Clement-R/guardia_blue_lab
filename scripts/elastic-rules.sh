#!/usr/bin/env bash
# Elastic prebuilt detection rules: install, enable the Windows ones, report health.
# Run on the siem VM:  sudo bash /vagrant/scripts/elastic-rules.sh <install|enable|status|disable-failing>
set -euo pipefail
cd /opt/elk
set -a; . ./.env; set +a
KB="https://localhost:5601"
kb() { curl -sS --fail-with-body --cacert /opt/elk/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
         -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -H 'elastic-api-version: 2023-10-31' "$@"; }

# Windows rules, minus machine-learning ones (they need a paid license)
WIN_QUERY='alert.attributes.tags:"OS: Windows" AND NOT alert.attributes.params.type:"machine_learning"'

count_rules() { kb "$KB/api/detection_engine/rules/_find?per_page=1&filter=$1" | jq -r '.total'; }

case "${1:-}" in
  install)
    kb -X POST "$KB/api/detection_engine/index" >/dev/null 2>&1 || true   # alerts index, if missing
    # One request only: the install can outlast it, and a retry would install the rules twice
    kb -m 900 -X PUT "$KB/api/detection_engine/rules/prepackaged" | jq -c . || true
    for _ in $(seq 1 60); do
      st=$(kb "$KB/api/detection_engine/rules/prepackaged/_status")
      [ "$(jq -r '.rules_not_installed' <<<"$st")" = "0" ] && break; sleep 10
    done
    jq -c '{rules_installed, rules_not_installed, rules_not_updated}' <<<"$st"
    ;;
  enable)
    kb -X POST "$KB/api/detection_engine/rules/_bulk_action" \
      -d "$(jq -n --arg q "$WIN_QUERY" '{action:"enable", query:$q}')" \
      | jq -c '.attributes.summary'
    echo "enabled rules in total: $(count_rules 'alert.attributes.enabled:true')"
    ;;
  status)
    # After at least one full rule cycle (5-10 min): last execution status of every enabled rule
    kb "$KB/api/detection_engine/rules/_find?per_page=10000&filter=alert.attributes.enabled:true" \
      | jq -r '.data[] | [(.execution_summary.last_execution.status // "not run yet"),
                          .name, (.execution_summary.last_execution.message // "" | gsub("\n";" ") | .[0:160])] | @tsv' \
      | sort > /opt/elk/elastic-rules-status.tsv
    cut -f1 /opt/elk/elastic-rules-status.tsv | sort | uniq -c
    echo "--- not succeeded:"; grep -v '^succeeded' /opt/elk/elastic-rules-status.tsv || true
    echo "(full list: /opt/elk/elastic-rules-status.tsv)"
    ;;
  disable-failing)
    ids=$(kb "$KB/api/detection_engine/rules/_find?per_page=10000&filter=alert.attributes.enabled:true" \
      | jq -c '[.data[] | select(.execution_summary.last_execution.status == "failed") | .id]')
    [ "$ids" = "[]" ] && { echo "no failing rules"; exit 0; }
    kb -X POST "$KB/api/detection_engine/rules/_bulk_action" \
      -d "$(jq -n --argjson ids "$ids" '{action:"disable", ids:$ids}')" | jq -c '.attributes.summary'
    ;;
  *) echo "usage: $0 install|enable|status|disable-failing" >&2; exit 1 ;;
esac
