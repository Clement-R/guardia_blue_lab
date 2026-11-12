#!/usr/bin/env bash
# SigmaHQ rules -> Elastic EQL detection rules, with a pinned pySigma toolchain.
# Run on the siem VM:  sudo bash /vagrant/scripts/sigma.sh <setup|convert|coverage>
#   setup     install the pinned toolchain in a venv and download the latest SigmaHQ Core+ release
#   convert   convert the Windows rules to Kibana rule objects (NDJSON), not imported yet
#   coverage  compare every field used by the converted rules with the fields present in Elasticsearch
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
    # Fields that exist in the Windows data streams (any type)
    curl -s --cacert $CA -u "elastic:${ELASTIC_PASSWORD}" \
      "https://localhost:9200/logs-windows.*,logs-system.*,logs-endpoint.events.*,logs-winlog.*/_field_caps?fields=*" \
      | jq -r '.fields | keys[]' > $S/es-fields.txt
    $V/bin/python - "$S" <<'PY'
import json, re, sys, collections
S = sys.argv[1]
known = set(open(f"{S}/es-fields.txt").read().split())
pat = re.compile(r'\??([A-Za-z_@][\w.@]*)\s*(?:==|!=|:|like~?|regex~?|in~?|>=|<=|>|<)\s')
missing = collections.Counter(); rules_missing = 0; total = 0
for line in open(f"{S}/converted.ndjson"):
    r = json.loads(line); total += 1
    fields = {f for f in pat.findall(r.get("query", "")) if "." in f or f[0].isupper()}
    gone = sorted(f for f in fields if f not in known)
    if gone:
        rules_missing += 1; missing.update(gone)
print(f"rules: {total}, using at least one field absent from Elasticsearch: {rules_missing}")
print("most frequent absent fields (field, rules):")
for f, n in missing.most_common(40):
    print(f"  {n:5d}  {f}")
PY
    ;;
  *) echo "usage: $0 setup|convert|coverage" >&2; exit 1 ;;
esac
