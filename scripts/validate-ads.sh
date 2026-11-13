#!/usr/bin/env bash
# Check whether the ADS rules fired for a validation run, and show the building blocks they were built from.
# Run on the siem VM, about 25 min after T1:
#   sudo bash /vagrant/scripts/validate-ads.sh <T0_iso> <T1_iso> [host]
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
CA=/opt/elk/certs/ca/ca.crt; ES="https://localhost:9200"
T0="$1"; T1="$2"; HOST="${3:-dc01}"
es() { curl -sS --fail-with-body --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' "$@"; }
END=$(python3 -c "import sys,datetime as d;s=sys.argv[1][:19];print((d.datetime.fromisoformat(s)+d.timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ'))" "$T1")

echo "== ADS alerts created between $T0 and $END =="
es "$ES/.alerts-security.alerts-default/_search" -d "{
  \"size\": 50, \"_source\": false, \"sort\": [{\"@timestamp\": \"asc\"}],
  \"fields\": [\"@timestamp\", \"kibana.alert.rule.name\", \"kibana.alert.original_time\", \"host.name\", \"user.name\",
               \"process.command_line\", \"kibana.alert.threshold_result.count\", \"kibana.alert.threshold_result.cardinality.value\",
               \"kibana.alert.building_block_type\"],
  \"query\": {\"bool\": {\"filter\": [
    {\"prefix\": {\"kibana.alert.rule.name\": \"ADS-\"}},
    {\"range\": {\"@timestamp\": {\"gte\": \"$T0\", \"lte\": \"$END\"}}}]}}}" \
| jq -r '
  if (.hits.hits | length) == 0 then "  (none)" else
  .hits.hits[].fields as $f |
  "  \($f["@timestamp"][0])  \($f["kibana.alert.rule.name"][0])\n" +
  "      event_time=\($f["kibana.alert.original_time"][0] // "-")  host=\($f["host.name"][0] // "-")  user=\($f["user.name"][0] // "-")" +
  "  building_block=\(if $f["kibana.alert.building_block_type"] then "yes" else "no (visible)" end)\n" +
  (if $f["kibana.alert.threshold_result.count"] then "      threshold: \($f["kibana.alert.threshold_result.count"][0]) building blocks, \($f["kibana.alert.threshold_result.cardinality.value"][0] // "?") distinct rules\n" else "" end) +
  (if $f["process.command_line"] then "      cmd: \($f["process.command_line"][0])\n" else "" end)
  end'

echo
echo "== Building-block alerts whose event time falls in the run (what ADS-2 counts) =="
es "$ES/.alerts-security.alerts-default/_search" -d "{
  \"size\": 0,
  \"query\": {\"bool\": {\"filter\": [
    {\"exists\": {\"field\": \"kibana.alert.building_block_type\"}},
    {\"term\": {\"host.name\": \"$HOST\"}},
    {\"range\": {\"kibana.alert.original_time\": {\"gte\": \"$T0\", \"lte\": \"$T1\"}}}]}},
  \"aggs\": {\"user\": {\"terms\": {\"field\": \"user.name\", \"missing\": \"(no user.name)\", \"size\": 10},
    \"aggs\": {\"distinct_rules\": {\"cardinality\": {\"field\": \"kibana.alert.rule.name\"}},
               \"rules\": {\"terms\": {\"field\": \"kibana.alert.rule.name\", \"size\": 20}}}}}}" \
| jq -r '.aggregations.user.buckets[] |
  "  user=\(.key): \(.doc_count) building blocks, \(.distinct_rules.value) distinct rules",
  (.rules.buckets[] | "      \(.doc_count)x  \(.key)")'
