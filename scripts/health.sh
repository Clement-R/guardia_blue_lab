#!/usr/bin/env bash
# Platform health at full rule load (milestone 07). Run on the siem VM:
#   sudo bash /vagrant/scripts/health.sh [samples] [seconds_between]     default: 10 samples, 30 s apart (5 min)
# Save the output as evidence:  vagrant ssh siem -c 'sudo bash /vagrant/scripts/health.sh' > evidence/health-$(date +%F).txt
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
CA=/opt/elk/certs/ca/ca.crt
ES="https://localhost:9200"; KB="https://localhost:5601"
es() { curl -sS --fail-with-body --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" "$@"; }
kb() { curl -sS --fail-with-body --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' "$@"; }
N=${1:-10}; GAP=${2:-30}
iso() { sed -E 's/\.[0-9]+Z$/Z/'; }

echo "=== Health check, $(date -u +%FT%TZ), Elastic $(es "$ES" | jq -r .version.number)"

echo "--- Cluster"
es "$ES/_cluster/health" | jq -r '"status \(.status), nodes \(.number_of_nodes), active shards \(.active_shards), unassigned \(.unassigned_shards) (replicas cannot be allocated on a single node)"'

echo "--- Detection rules enabled"
kb "$KB/api/detection_engine/rules/_find?per_page=10000&filter=alert.attributes.enabled:true" > /tmp/rules.json
jq -r '.data | group_by(if (.tags|index("sigma-deploy")) then "sigma" elif .immutable then "elastic prebuilt" else "custom" end)
       | .[] | "\(length)\t\(if (.[0].tags|index("sigma-deploy")) then "sigma" elif .[0].immutable then "elastic prebuilt" else "custom" end)"' /tmp/rules.json
jq -r '"total enabled: \(.data | length)"' /tmp/rules.json

echo "--- Rule execution (last run of every enabled rule)"
jq -r '.data[] | .execution_summary.last_execution.status // "not run yet"' /tmp/rules.json | sort | uniq -c
# Late = last run older than two intervals (interval like "5m" / "10m" / "1h")
jq -r --argjson now "$(date -u +%s)" '
  def secs: capture("(?<n>[0-9]+)(?<u>[smhd])") | (.n|tonumber) * ({"s":1,"m":60,"h":3600,"d":86400}[.u]);
  [.data[] | select(.execution_summary.last_execution.date != null)
   | select(($now - (.execution_summary.last_execution.date | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601)) > 2 * (.interval | secs))]
  | "rules running late (> 2 intervals since last run): \(length)"' /tmp/rules.json
jq -r '[.data[].execution_summary.last_execution.metrics.total_search_duration_ms // empty] | sort
       | if length > 0 then "rule search time ms: median \(.[length/2|floor]), p95 \(.[length*0.95|floor]), max \(.[-1])" else empty end' /tmp/rules.json

echo "--- Kibana task manager (rule scheduling)"
kb "$KB/api/task_manager/_health" | jq -r '"status \(.status); scheduling delay (drift) ms: p50 \(.stats.runtime.value.drift.p50 // "?"), p99 \(.stats.runtime.value.drift.p99 // "?"); load p50 \(.stats.runtime.value.load.p50 // "?")%"'

echo "--- Ingestion delay (event.ingested - @timestamp, last 500 events from dc01)"
es -H 'Content-Type: application/json' "$ES/logs-windows.*,logs-system.*,logs-endpoint.events.*/_search" -d '{
  "size": 500, "sort": [{"@timestamp": "desc"}], "_source": ["@timestamp", "event.ingested"],
  "query": {"bool": {"filter": [{"term": {"host.name": "dc01"}}, {"exists": {"field": "event.ingested"}}]}}}' \
| jq -r '[.hits.hits[]._source | ((.event.ingested | sub("\\.[0-9]+";"") | sub("\\+00:00$";"Z") | fromdateiso8601)
                                 - (."@timestamp" | sub("\\.[0-9]+";"") | sub("\\+00:00$";"Z") | fromdateiso8601))] | sort
         | "seconds: min \(.[0]), median \(.[length/2|floor]), max \(.[-1]) (n=\(length))"'

echo "--- Elasticsearch heap and memory-limit trips: $N samples, ${GAP}s apart"
for i in $(seq 1 "$N"); do
  es "$ES/_nodes/stats/jvm,breaker" | jq -r '.nodes[] | "\(.jvm.mem.heap_used_percent) \([.breakers[].tripped] | add)"'
  if [ "$i" -lt "$N" ]; then sleep "$GAP"; fi
done | awk '{h[NR]=$1; s+=$1; if(NR==1||$1<mn)mn=$1; if($1>mx)mx=$1; t=$2}
            END{printf "heap %%: min %d, mean %.0f, max %d; memory-limit trips (cumulative): %d\n", mn, s/NR, mx, t}'

echo "--- Container memory"
docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}} CPU' | sort
echo "--- Disk"
df -h / | tail -1 | awk '{print "siem VM root: " $3 " used of " $2 " (" $5 ")"}'
