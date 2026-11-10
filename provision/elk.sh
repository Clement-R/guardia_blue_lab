#!/usr/bin/env bash
# Deploy Elasticsearch + Kibana via Docker Compose
set -euo pipefail

# Local copy (to avoid issues on shared folders)
rm -rf /opt/elk
mkdir -p /opt/elk
cp /vagrant/elk/docker-compose.yml /vagrant/elk/.env /opt/elk/
sed -i 's/\r$//' /opt/elk/.env /opt/elk/docker-compose.yml
cd /opt/elk

set -a
. ./.env
set +a

docker compose up -d elasticsearch

echo "Waiting for Elasticsearch's API"
for i in $(seq 1 60); do
  if curl -s -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200 >/dev/null; then
    break
  fi
  sleep 5
done

# Interal user's password used by Kibana
curl -s -u "elastic:${ELASTIC_PASSWORD}" -X POST \
  -H "Content-Type: application/json" \
  http://localhost:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}"

docker compose up -d kibana
echo "Kibana : http://10.77.77.10:5601 (utilisateur elastic)"
