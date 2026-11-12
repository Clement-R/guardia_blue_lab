# Sigma

`scripts/sigma.sh` converts SigmaHQ Windows rules to Elastic EQL rules with a pinned pySigma toolchain.

`elastic-agent-overrides.yml` (added after the coverage check) holds site field-name corrections,
each verified against a real event before use.
