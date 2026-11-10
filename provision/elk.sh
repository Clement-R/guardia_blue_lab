#!/usr/bin/env bash
# Deploy Elasticsearch + Kibana + Fleet Server with Docker Compose. Safe to re-run.
set -euo pipefail

SIEM_IP="10.77.77.10"
ES="http://localhost:9200"
KB="http://localhost:5601"

mkdir -p /opt/elk
cp /vagrant/elk/docker-compose.yml /opt/elk/
sed -i 's/\r$//' /opt/elk/docker-compose.yml
cd /opt/elk

# .env: keep the existing one (the Elasticsearch volume holds matching passwords),
# else use the repo's copy, else generate random secrets from .env.example.
if [ ! -f .env ]; then
  if [ -f /vagrant/elk/.env ]; then
    cp /vagrant/elk/.env .env
  else
    cp /vagrant/elk/.env.example .env
    sed -i "s|^ELASTIC_PASSWORD=.*|ELASTIC_PASSWORD=$(openssl rand -hex 12)|" .env
    sed -i "s|^KIBANA_PASSWORD=.*|KIBANA_PASSWORD=$(openssl rand -hex 12)|"   .env
    sed -i "s|^KIBANA_KEY=.*|KIBANA_KEY=$(openssl rand -hex 32)|"             .env
  fi
  sed -i 's/\r$//' .env
  chmod 600 .env
fi

set_env() {   # set_env KEY VALUE
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}
load_env() { set -a; . ./.env; set +a; }
es() { curl -sf -u "elastic:${ELASTIC_PASSWORD}" "$@"; }
kb() { curl -sf -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }
wait_for() {  # wait_for LABEL COMMAND...
  local label="$1"; shift
  for _ in $(seq 1 90); do "$@" >/dev/null 2>&1 && return 0; sleep 5; done
  echo "Timeout waiting for ${label}" >&2; exit 1
}

load_env

# --- Elasticsearch ---
docker compose up -d elasticsearch
wait_for "Elasticsearch" es "$ES"

# Password of the internal user Kibana connects as
es -X POST -H 'Content-Type: application/json' \
  "$ES/_security/user/kibana_system/_password" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" >/dev/null

# --- Kibana ---
docker compose up -d kibana
wait_for "Kibana" bash -c "curl -sf -u 'elastic:${ELASTIC_PASSWORD}' $KB/api/status | jq -e '.status.overall.level==\"available\"'"

# --- Fleet configuration in Kibana ---
kb -X POST "$KB/api/fleet/setup" >/dev/null

# Fleet Server policy with a fixed ID, referenced by the container
if ! kb "$KB/api/fleet/agent_policies/fleet-server-policy" >/dev/null 2>&1; then
  kb -X POST "$KB/api/fleet/agent_policies?sys_monitoring=false" \
    -d '{"id":"fleet-server-policy","name":"Fleet Server Policy","namespace":"default","has_fleet_server":true}' >/dev/null
  ver=$(kb "$KB/api/fleet/epm/packages/fleet_server" | jq -r '.item.version // .response.version')
  kb -X POST "$KB/api/fleet/package_policies" \
    -d "{\"name\":\"fleet_server-1\",\"namespace\":\"default\",\"policy_ids\":[\"fleet-server-policy\"],\"package\":{\"name\":\"fleet_server\",\"version\":\"${ver}\"}}" >/dev/null \
    || echo "WARN: could not add the Fleet Server integration; add it once in Kibana (Fleet > Agent policies)" >&2
fi

# URLs that agents use to reach the SIEM from outside Docker
body="{\"name\":\"default\",\"host_urls\":[\"http://${SIEM_IP}:8220\"],\"is_default\":true}"
host_id=$(kb "$KB/api/fleet/fleet_server_hosts" | jq -r '[.items[]|select(.is_default)][0].id // empty')
if [ -n "$host_id" ]; then kb -X PUT  "$KB/api/fleet/fleet_server_hosts/${host_id}" -d "$body" >/dev/null
else                       kb -X POST "$KB/api/fleet/fleet_server_hosts"            -d "$body" >/dev/null; fi

out_id=$(kb "$KB/api/fleet/outputs" | jq -r '[.items[]|select(.is_default)][0].id')
kb -X PUT "$KB/api/fleet/outputs/${out_id}" \
  -d "{\"name\":\"default\",\"type\":\"elasticsearch\",\"hosts\":[\"http://${SIEM_IP}:9200\"],\"is_default\":true,\"is_default_monitoring\":true}" >/dev/null

# --- Service token: reuse it if Elasticsearch accepts it, else create a new one ---
if [ -z "${SERVICE_TOKEN:-}" ] || ! curl -sf -H "Authorization: Bearer ${SERVICE_TOKEN}" "$ES/_security/_authenticate" >/dev/null; then
  token=$(es -X POST "$ES/_security/service/elastic/fleet-server/credential/token/fleet-$(date +%s)" | jq -r '.token.value')
  set_env SERVICE_TOKEN "$token"
  load_env
fi

# --- Fleet Server ---
docker compose up -d fleet-server

echo "Kibana:       http://${SIEM_IP}:5601 (user: elastic, password in /opt/elk/.env)"
echo "Fleet Server: http://${SIEM_IP}:8220"