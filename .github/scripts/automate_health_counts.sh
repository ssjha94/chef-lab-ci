#!/usr/bin/env bash
set -euo pipefail

if [ -z "${AUTOMATE_URL:-}" ] || [ -z "${AUTOMATE_API_TOKEN:-}" ]; then
  echo "AUTOMATE_URL/AUTOMATE_API_TOKEN not set, skipping Automate health check."
  {
    echo "success_count=0"
    echo "failed_count=0"
    echo "skipped_count=0"
    echo "total_count=0"
    echo "base_total_count=0"
  } >> "${GITHUB_OUTPUT}"
  exit 0
fi

if [ -z "${POLICY_GROUP:-}" ] || [ -z "${POLICY_NAME:-}" ]; then
  echo "ERROR: POLICY_GROUP and POLICY_NAME must be set for Automate health checks."
  exit 1
fi

endpoint="${AUTOMATE_URL%/}/api/v0/cfgmgmt/stats/node_counts"
filters=("policy_group:${POLICY_GROUP}" "policy_name:${POLICY_NAME}")

build_url() {
  local extra_filter="${1:-}"
  local query=""
  local filter
  local merged_filters=("${filters[@]}")
  if [ -n "$extra_filter" ]; then
    merged_filters+=("$extra_filter")
  fi

  for filter in "${merged_filters[@]}"; do
    encoded="$(ruby -ruri -e 'print URI.encode_www_form_component(ARGV[0])' "$filter")"
    if [ -z "$query" ]; then
      query="?filter=${encoded}"
    else
      query="${query}&filter=${encoded}"
    fi
  done
  printf '%s%s\n' "$endpoint" "$query"
}

summarize_response() {
  ruby -rjson -e '
    data = JSON.parse(STDIN.read)
    counts = Hash.new(0)
    walk = lambda do |obj|
      case obj
      when Hash
        if obj["status"] && obj["count"]
          counts[obj["status"].to_s.downcase] += obj["count"].to_i
        elsif obj["name"] && obj["count"]
          counts[obj["name"].to_s.downcase] += obj["count"].to_i
        else
          obj.each do |k, v|
            key = k.to_s.downcase
            if v.is_a?(Numeric) && %w[success failed failure error unreachable skipped total].include?(key)
              counts[key] += v.to_i
            else
              walk.call(v)
            end
          end
        end
      when Array
        obj.each { |v| walk.call(v) }
      end
    end

    walk.call(data)
    success = counts["success"]
    failed = counts["failed"] + counts["failure"] + counts["error"] + counts["unreachable"]
    skipped = counts["skipped"]
    total = counts["total"]
    total = success + failed + skipped if total.zero?
    puts "#{success} #{failed} #{skipped} #{total}"
  '
}

base_url="$(build_url)"
echo "Calling Automate node_counts API for ${POLICY_NAME}/${POLICY_GROUP}"
base_response="$(curl -fsS -H "api-token: ${AUTOMATE_API_TOKEN}" "$base_url")"
read -r base_success base_failed base_skipped base_total <<< "$(printf '%s\n' "$base_response" | summarize_response)"

success_url="$(build_url "status:success")"
success_response="$(curl -fsS -H "api-token: ${AUTOMATE_API_TOKEN}" "$success_url")"
read -r status_success _ _ _ <<< "$(printf '%s\n' "$success_response" | summarize_response)"

status_failed=0
for st in failed failure error unreachable; do
  st_url="$(build_url "status:${st}")"
  st_response="$(curl -fsS -H "api-token: ${AUTOMATE_API_TOKEN}" "$st_url")"
  read -r _ st_failed _ _ <<< "$(printf '%s\n' "$st_response" | summarize_response)"
  status_failed=$((status_failed + st_failed))
done

skipped_url="$(build_url "status:skipped")"
skipped_response="$(curl -fsS -H "api-token: ${AUTOMATE_API_TOKEN}" "$skipped_url")"
read -r _ _ status_skipped _ <<< "$(printf '%s\n' "$skipped_response" | summarize_response)"

status_total=$((status_success + status_failed + status_skipped))
if [ "$status_total" -eq 0 ] && [ "$base_total" -gt 0 ]; then
  status_total="$base_total"
fi

echo "Automate base summary: success=${base_success}, failed=${base_failed}, skipped=${base_skipped}, total=${base_total}"
echo "Automate filtered summary (status filters): success=${status_success}, failed=${status_failed}, skipped=${status_skipped}, total=${status_total}"
{
  echo "success_count=${status_success}"
  echo "failed_count=${status_failed}"
  echo "skipped_count=${status_skipped}"
  echo "total_count=${status_total}"
  echo "base_total_count=${base_total}"
} >> "${GITHUB_OUTPUT}"
