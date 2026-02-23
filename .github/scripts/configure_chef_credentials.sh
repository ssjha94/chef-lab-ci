#!/usr/bin/env bash
set -euo pipefail

for req in CHEF_SERVER_URL CHEF_USER CHEF_USER_KEY; do
  if [ -z "${!req:-}" ]; then
    echo "ERROR: Missing required secret ${req}. Check repository secrets and environment secret overrides."
    exit 1
  fi
done

case "${CHEF_SERVER_URL}" in
  http://*|https://*|chefzero://*) ;;
  *)
    echo "ERROR: CHEF_SERVER_URL is invalid. It must start with http://, https://, or chefzero://."
    exit 1
    ;;
esac

mkdir -p ~/.chef
cat > ~/.chef/knife.rb <<'EOF'
chef_server_url  ENV['CHEF_SERVER_URL']
node_name        ENV['CHEF_USER']
client_key       File.join(ENV['HOME'], '.chef', 'ci-user.pem')
org_name         ENV['CHEF_ORG'] if ENV['CHEF_ORG']
ssl_verify_mode  (ENV['CHEF_SSL_VERIFY'] || ':verify_peer')
EOF

printf '%s' "${CHEF_USER_KEY}" > ~/.chef/ci-user.pem
chmod 600 ~/.chef/ci-user.pem
