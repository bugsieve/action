#!/usr/bin/env bash
# Starts a Bugsieve scan, waits for it, writes a job summary and applies the fail-on policy.
set -euo pipefail

out() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }
summary() { echo "$1" >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"; }
poll_seconds="${BUGSIEVE_POLL_SECONDS:-15}"

if [[ -z "${BUGSIEVE_TOKEN:-}" ]]; then
  echo "::notice::No Bugsieve token (secrets are not passed to pull requests from forks). Skipping the scan."
  out status skipped
  exit 0
fi
echo "::add-mask::$BUGSIEVE_TOKEN"

api() {
  curl -sS -w '\n%{http_code}' -H "Authorization: Bearer $BUGSIEVE_TOKEN" -H 'Accept: application/json' -H 'Content-Type: application/json' "$@"
}

body=$(jq -n --arg url "$BUGSIEVE_REPOSITORY" --arg ref "$BUGSIEVE_REF" '{url: $url, ref: (if $ref == "" then null else $ref end)}')
response=$(api -X POST "${BUGSIEVE_SERVER%/}/api/v1/scans" -d "$body")
code=$(tail -n1 <<<"$response"); json=$(sed '$d' <<<"$response")

case "$code" in
  202) ;;
  429) echo "::warning::Bugsieve did not start a scan: $(jq -r '.message' <<<"$json"). The build is not failed for this."; out status skipped; exit 0 ;;
  401|403) echo "::error::Bugsieve refused the token (HTTP $code). Create a new one on your Bugsieve profile."; exit 1 ;;
  422) echo "::error::$(jq -r '.errors.url[0] // .message' <<<"$json")"; exit 1 ;;
  *) echo "::error::Bugsieve answered HTTP $code."; exit 1 ;;
esac

id=$(jq -r '.data.id' <<<"$json"); out scan-id "$id"
deadline=$(( $(date +%s) + BUGSIEVE_TIMEOUT_MINUTES * 60 ))
status=queued

while [[ "$status" == queued || "$status" == running ]]; do
  if (( $(date +%s) > deadline )); then
    echo "::warning::The Bugsieve scan did not finish within ${BUGSIEVE_TIMEOUT_MINUTES} minutes."; out status timeout; exit 0
  fi
  sleep "$poll_seconds"
  response=$(api "${BUGSIEVE_SERVER%/}/api/v1/scans/$id")
  code=$(tail -n1 <<<"$response"); json=$(sed '$d' <<<"$response")
  [[ "$code" == 200 ]] || { echo "::warning::Bugsieve answered HTTP $code while waiting; retrying."; continue; }
  status=$(jq -r '.data.status' <<<"$json")
done

out status "$status"
url=$(jq -r '.data.links.web' <<<"$json"); out report-url "$url"

if [[ "$status" == failed ]]; then
  echo "::error::Bugsieve scan failed: $(jq -r '.data.failure' <<<"$json")"; exit 1
fi

read -r critical high medium exploited total < <(jq -r '.data.counts | "\(.critical) \(.high) \(.medium) \(.exploited) \(.total)"' <<<"$json")
out critical "$critical"; out high "$high"; out exploited "$exploited"

summary "### Bugsieve: $(jq -r '.data.repository' <<<"$json") @ $(jq -r '.data.branch // "default branch"' <<<"$json")"
summary ""
summary "| Exploited | Critical | High | Medium | Total |"
summary "|---|---|---|---|---|"
summary "| $exploited | $critical | $high | $medium | $total |"
summary ""
summary "[Open the full report]($url)"

case "$BUGSIEVE_FAIL_ON" in
  none) over=0 ;;
  exploited) over=$exploited ;;
  critical) over=$(( exploited + critical )) ;;
  high) over=$(( exploited + critical + high )) ;;
  medium) over=$(( exploited + critical + high + medium )) ;;
  *) echo "::error::fail-on must be none, exploited, critical, high or medium."; exit 1 ;;
esac

if [[ "$over" -gt 0 ]]; then
  echo "::error::Bugsieve found findings at or above '$BUGSIEVE_FAIL_ON'. See $url"
  exit 1
fi
