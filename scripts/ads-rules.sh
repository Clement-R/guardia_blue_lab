#!/usr/bin/env bash
# Create or update the ADS detection rules (detections/ads-rules.json): ADS-1 archiver, ADS-2 recon/staging burst.
# Run on the siem VM:  sudo bash /vagrant/scripts/ads-rules.sh
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
KB="https://localhost:5601"
kb() { curl -sS --cacert /opt/elk/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' \
         -H 'elastic-api-version: 2023-10-31' -H 'Content-Type: application/json' -w '\n%{http_code}' "$@"; }
jq -c '.[]' /vagrant/detections/ads-rules.json | while read -r rule; do
  name=$(jq -r .name <<<"$rule")
  out=$(kb -X POST "$KB/api/detection_engine/rules" -d "$rule"); code=$(tail -1 <<<"$out")
  if [ "$code" = "409" ]; then
    out=$(kb -X PUT "$KB/api/detection_engine/rules" -d "$rule"); code=$(tail -1 <<<"$out"); verb=updated
  else verb=created; fi
  if [ "$code" = "200" ]; then echo "$verb: $name"
  else echo "ERROR ($code) $name: $(head -n -1 <<<"$out" | jq -c '.message // .' 2>/dev/null | cut -c1-300)"; fi
done
