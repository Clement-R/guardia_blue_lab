#!/usr/bin/env bash
# Score an emulation run: classify each test's outcome and time-to-detect from alerts in Elasticsearch.
# Run on the siem VM:
#   sudo bash /vagrant/scripts/score-run.sh <execlog.csv on the DC OR a local markers file> <T0_iso> <T1_iso> [host]
# execlog/markers give per-test start times; a test window runs start->next start, last window ends at T1.
# Outcome: Alerted | Building-block only | Telemetry only | Not observed | Not executed(from execlog exit!=0)
set -euo pipefail
cd /opt/elk; set -a; . ./.env; set +a
CA=/opt/elk/certs/ca/ca.crt; ES="https://localhost:9200"
HOST="${4:-dc01}"
MARKERS="$1"; T0="$2"; T1="$3"
[ -f "$MARKERS" ] || { echo "Provide the run's markers/execlog file (copy it off the DC first): $MARKERS" >&2; exit 1; }

es() { curl -sS --fail-with-body --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' "$@"; }

# Parse "N start (UTC): <iso>  <tech> <name>" lines from the markers file into: start<TAB>tech<TAB>name
python3 - "$MARKERS" "$T1" > /tmp/windows.tsv <<'PY'
import sys, re
raw=open(sys.argv[1],'rb').read()
if raw[:2] in (b'\xff\xfe', b'\xfe\xff'): text=raw.decode('utf-16')
elif raw[:3]==b'\xef\xbb\xbf': text=raw.decode('utf-8-sig')
else: text=raw.decode('utf-8','replace')
lines=text.splitlines(); T1=sys.argv[2]
rows=[]
for l in lines:
    m=re.match(r'\s*(\d+)\s+start \(UTC\):\s*(\S+)\s+(T\S+)\s+(.*)', l)
    if m: rows.append([m.group(2), m.group(3), m.group(4).strip()])
for i,r in enumerate(rows):
    end = rows[i+1][0] if i+1<len(rows) else T1
    print("\t".join([r[0], end, r[1], r[2]]))
PY
n=$(wc -l < /tmp/windows.tsv)
[ "$n" -gt 0 ] || { echo "No test-start markers parsed from $MARKERS" >&2; exit 1; }
echo -e "tech\tname\toutcome\tvisible\tbb\trule_sets\tTTD_s\ttop_rules"

# Building-block rule names to treat as non-visible (extend as needed)
BB_FILTER='kibana.alert.building_block_type'
total_visible=0; total_tests=0; total_alerted=0
while IFS=$'\t' read -r start end tech name; do
  total_tests=$((total_tests+1))
  # Alerts whose triggering event time falls in [start,end) for this host
  q=$(cat <<JSON
{"size":0,"query":{"bool":{"filter":[
  {"term":{"host.name":"$HOST"}},
  {"range":{"kibana.alert.original_time":{"gte":"$start","lt":"$end"}}}]}},
"aggs":{
  "visible":{"filter":{"bool":{"must_not":{"exists":{"field":"$BB_FILTER"}}}},
            "aggs":{"rules":{"terms":{"field":"kibana.alert.rule.name","size":5}},
                    "first":{"min":{"field":"@timestamp"}}}},
  "bb":{"filter":{"exists":{"field":"$BB_FILTER"}}}}}
JSON
)
  r=$(es "$ES/.alerts-security.alerts-default/_search" -d "$q")
  vis=$(jq -r '.aggregations.visible.doc_count' <<<"$r")
  bb=$(jq -r '.aggregations.bb.doc_count' <<<"$r")
  first=$(jq -r '.aggregations.visible.first.value_as_string // empty' <<<"$r")
  rules=$(jq -r '[.aggregations.visible.rules.buckets[].key] | join("; ")' <<<"$r")
  # rule-set tag: does any top rule look like sigma (prefix "SIGMA") vs elastic
  rs=$(jq -r '[.aggregations.visible.rules.buckets[].key] | (if any(startswith("SIGMA")) then "Sigma" else "" end) + (if any(startswith("SIGMA")|not) then " Elastic" else "" end)' <<<"$r" | sed 's/^ //')
  if [ "$vis" -gt 0 ]; then
    outcome="Alerted"; total_alerted=$((total_alerted+1))
    ttd=$(python3 -c "import sys;from datetime import datetime as d;a=d.fromisoformat('$first'.replace('Z','+00:00'));b=d.fromisoformat('$start'.replace('Z','+00:00'));print(int((a-b).total_seconds()))" 2>/dev/null || echo "?")
  elif [ "$bb" -gt 0 ]; then outcome="Building-block only"; ttd="-"
  else outcome="Telemetry/Not observed"; ttd="-"; fi   # distinguish with Discover if needed
  total_visible=$((total_visible+vis))
  echo -e "$tech\t$name\t$outcome\t$vis\t$bb\t${rs:--}\t$ttd\t${rules:--}"
done < /tmp/windows.tsv

echo "---"
echo "tests: $total_tests, alerted: $total_alerted, total visible alerts attributed: $total_visible"
echo "(Telemetry-only vs Not-observed: confirm in Discover logs-* for the few non-alerting windows)"
