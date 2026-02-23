#!/bin/bash
# user-data.sh - Chef node bootstrap script
# This script runs on first boot of EC2 instances

set -e

echo "[$(date)] Starting Chef node bootstrap..."

# Install Chef Infra Client (if not present)
if ! command -v chef-client &> /dev/null; then
  echo "[$(date)] Installing Chef Infra Client..."
  curl -L https://omnitruck.chef.io/install.sh | sudo bash -s -- -c stable -P chef-infra-client
else
  echo "[$(date)] Chef Infra Client already installed"
fi

# Create /etc/chef directory
echo "[$(date)] Creating Chef configuration directory..."
mkdir -p /etc/chef
chmod 755 /etc/chef

# Write client.pem (provided by Terraform)
echo "[$(date)] Writing client.pem..."
cat > /etc/chef/client.pem <<'CLIENTPEM'
${client_pem}
CLIENTPEM

chmod 600 /etc/chef/client.pem

# Get hostname for Chef client name
HOSTNAME=$(hostname -f)

# Write client.rb configuration
echo "[$(date)] Writing /etc/chef/client.rb..."
cat > /etc/chef/client.rb <<CLIENTRB
# Chef Infra Client configuration
log_level                :info
log_location             STDOUT
node_name                "$HOSTNAME"
client_key               "/etc/chef/client.pem"
chef_server_url          "${chef_server_url}/organizations/${chef_org}"
policy_name              "automate_compliance"
policy_group             "${policy_group}"
verify_api_cert          false

# Data collector for Automate
data_collector.server_url   "https://ssj-chef-automate-osaka.success.chef.co/data-collector/v0/"
data_collector.token        "pwkGbKXL80Z2TQavQWG4PiC-jtw="

# Run in policy mode
use_policyfile true

# Local mode cache
file_cache_path          "/var/cache/chef"
CLIENTRB

chmod 600 /etc/chef/client.rb

# First chef-client run (may fail if node not ready)
echo "[$(date)] Running initial chef-client..."
chef-client -l info || {
  echo "[$(date)] First run failed, retrying in 30 seconds..."
  sleep 30
  chef-client -l info
}

echo "[$(date)] Chef node bootstrap complete!"

# Cleanup: remove client.pem if desired (optional - keep for troubleshooting)
# rm -f /etc/chef/client.pem
