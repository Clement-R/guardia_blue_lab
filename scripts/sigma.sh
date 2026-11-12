#!/usr/bin/env bash
# SigmaHQ rules -> Elastic EQL detection rules, with a pinned pySigma toolchain.
# Run on the siem VM:  sudo bash /vagrant/scripts/sigma.sh <setup|convert|coverage|verify>
#   setup     install the pinned toolchain in a venv and download the latest SigmaHQ Core+ release
#   convert   convert the Windows rules to Kibana rule objects (NDJSON), not imported yet
#   coverage  check that every field a converted rule uses is populated in the channel it reads
set -euo pipefail
S=/opt/sigma
V=$S/venv
cd /opt/elk; set -a; . ./.env; set +a
CA=/opt/elk/certs/ca/ca.crt

# Same pins as the reference build: newer sigma-cli needs pySigma 2.x, which this backend does not support
PINS="sigma-cli==3.1.0 pySigma==1.5.1 pySigma-backend-elasticsearch==2.1.1 pySigma-pipeline-sysmon==2.0.0 pySigma-pipeline-windows==2.0.1"

case "${1:-}" in
  setup)
    apt-get install -y -q python3-venv unzip >/dev/null
    mkdir -p $S
    [ -x $V/bin/sigma ] || python3 -m venv $V
    $V/bin/pip install -q --upgrade pip
    $V/bin/pip install -q $PINS
    # Latest SigmaHQ release, Core+ package (rules unpinned on purpose: content stays current)
    rel=$(curl -s https://api.github.com/repos/SigmaHQ/sigma/releases/latest)
    tag=$(jq -r .tag_name <<<"$rel")
    url=$(jq -r '.assets[] | select(.name=="sigma_core+.zip") | .browser_download_url' <<<"$rel")
    [ -n "$url" ] || { echo "sigma_core+.zip not found in release $tag" >&2; exit 1; }
    rm -rf "$S/rules-$tag"; mkdir -p "$S/rules-$tag"
    curl -sL "$url" -o "$S/sigma_core+.zip" && unzip -q -o "$S/sigma_core+.zip" -d "$S/rules-$tag"
    ln -sfn "$S/rules-$tag" $S/rules
    { echo "sigma_release=$tag"; echo "downloaded_utc=$(date -u +%FT%TZ)"; $V/bin/pip freeze | grep -i sigma; } | tee $S/versions.txt
    $V/bin/sigma list pipelines | grep -Ei 'sysmon|windows|ecs' || true
    echo "windows rules: $(find $S/rules/ -path '*windows*' -name '*.yml' | wc -l)"
    ;;

  convert)
    win=$(find $S/rules/ -type d -name windows | head -1)
    over=(); [ -f /vagrant/sigma/elastic-agent-overrides.yml ] && over=(-p /vagrant/sigma/elastic-agent-overrides.yml)
    # Pipelines in priority order: sysmon (categories -> Sysmon event IDs), windows-logsources
    # (services -> channels), ecs_windows (Sigma -> ECS field names), then the site overrides
    $V/bin/sigma convert -t eql -f siem_rule_ndjson --skip-unsupported \
      -p sysmon -p windows-logsources -p ecs_windows "${over[@]}" \
      -o $S/converted.ndjson "$win" 2> $S/convert-errors.log || true
    echo "converted rules: $(wc -l < $S/converted.ndjson)"
    echo "conversion errors/skips: $(grep -c . $S/convert-errors.log || true) lines (see $S/convert-errors.log)"
    ;;

  coverage)
    # For every converted rule: is each field it uses actually populated in the log
    # channel the rule reads? (A field can be mapped by an index template yet never filled.)
    ELASTIC_PASSWORD="$ELASTIC_PASSWORD" $V/bin/python - "$S" "$CA" <<'PY'
import json, re, sys, ssl, base64, os, collections, urllib.request
S, CA = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(cafile=CA)
auth = "Basic " + base64.b64encode(f"elastic:{os.environ['ELASTIC_PASSWORD']}".encode()).decode()
IDX = "logs-windows.*,logs-system.*,logs-winlog.*,logs-endpoint.events.*"
def count(field, channel):
    flt = [{"exists": {"field": field}}]
    if channel: flt.append({"term": {"winlog.channel": channel}})
    req = urllib.request.Request(f"https://localhost:9200/{IDX}/_count", method="POST",
        data=json.dumps({"query": {"bool": {"filter": flt}}}).encode(),
        headers={"Authorization": auth, "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, context=ctx))["count"]

chan_re  = re.compile(r'winlog\.channel\s*(?::|==)\s*"([^"]+)"')
str_re   = re.compile(r'"(?:\\.|[^"\\])*"')
field_re = re.compile(r'\??([A-Za-z_@][\w.@]*)\s*(?:==|!=|:|like~?|regex~?|in~?|>=|<=|>|<)\s')
cache, missing, rows = {}, collections.Counter(), []
rules = [json.loads(l) for l in open(f"{S}/converted.ndjson")]
for r in rules:
    q = r.get("query", "")
    chans = sorted(set(chan_re.findall(q))) or [None]
    fields = {f for f in field_re.findall(str_re.sub('""', q)) if "." in f}
    gone = []
    for f in sorted(fields):
        n = 0
        for c in chans:
            k = (f, c)
            if k not in cache: cache[k] = count(f, c)
            n += cache[k]
        if n == 0: gone.append(f)
    for f in gone: missing[(f, chans[0] or "any channel")] += 1
    rows.append((r.get("name", "?"), ",".join(c or "-" for c in chans), " ".join(gone)))
with open(f"{S}/coverage.tsv", "w") as out:
    for row in rows: out.write("\t".join(row) + "\n")
bad = sum(1 for r in rows if r[2])
print(f"rules: {len(rows)}; with at least one field never populated in the channel they read: {bad}")
print("note: a rule can also be silent only because no matching activity has happened yet")
print("most frequent (rules, field, channel):")
for (f, c), n in missing.most_common(40):
    print(f"  {n:5d}  {f:45s} {c}")
print(f"(per-rule detail: {S}/coverage.tsv)")
PY
    ;;
  verify)
    # Evidence for each override: the target field is populated in the Sysmon channel, with a sample value
    for f in process.parent.executable process.executable registry.data.strings file.code_signature.trusted \
             process.parent.executable.caseless winlog.event_data.Details file.code_signature.signed; do
      r=$(curl -s --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' \
        "https://localhost:9200/logs-windows.sysmon_operational-*/_search" -d "{\"size\":1,\"track_total_hits\":true,
         \"query\":{\"bool\":{\"filter\":[{\"exists\":{\"field\":\"$f\"}}]}},\"_source\":[\"event.code\",\"$f\"]}")
      printf '%-38s docs=%-7s sample=%s\n' "$f" "$(jq -r '.hits.total.value' <<<"$r")" \
        "$(jq -c '.hits.hits[0]._source // {}' <<<"$r" | cut -c1-110)"
    done
    ;;
  *) echo "usage: $0 setup|convert|coverage|verify" >&2; exit 1 ;;
esac
