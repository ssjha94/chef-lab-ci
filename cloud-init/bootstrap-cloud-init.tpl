#cloud-config
package_update: true

write_files:
  - path: /var/lib/cloud/scripts/per-once/chef-bootstrap.sh
    permissions: '0755'
    owner: root:root
    content: |
      #!/bin/bash
      set -euo pipefail
      exec > >(tee /var/log/chef-bootstrap.log) 2>&1
      echo "=== Chef Bootstrap started at $(date) ==="

      # ── Variables replaced at launch time ───────────────────────────────
      CHEF_SERVER_URL="__CHEF_SERVER_URL__"
      NODE_NAME="__NODE_NAME__"
      S3_URI="__S3_URI__"
      RUN_LIST='__RUN_LIST__'
      # ────────────────────────────────────────────────────────────────────

      # Install AWS CLI + Chef Infra Client
      apt-get update -y
      apt-get install -y awscli
      curl -fsSL https://omnitruck.chef.io/install.sh | bash -s -- -P chef -c stable

      mkdir -p /etc/chef
      chmod 700 /etc/chef

      echo "Fetching bootstrap client key from ${S3_URI}"
      aws s3 cp "${S3_URI}" /etc/chef/bootstrap-client.pem
      chmod 600 /etc/chef/bootstrap-client.pem

      # Temporary config for first run (auth as bootstrap-client via -K)
      cat > /etc/chef/bootstrap-client.rb <<EOF
chef_server_url          "${CHEF_SERVER_URL}"
node_name                "${NODE_NAME}"
client_key               "/etc/chef/client.pem"
validation_client_name   "bootstrap-client"
validation_key           "/etc/chef/bootstrap-client.pem"
chef_license             "accept-silent"
ssl_verify_mode          :verify_peer
EOF

      # First-boot JSON
      cat > /etc/chef/first-boot.json <<EOF
{
  "run_list": ${RUN_LIST}
}
EOF

      echo "=== Running chef-client (validator-less via -K) as '${NODE_NAME}' ==="
      chef-client \
        -c /etc/chef/bootstrap-client.rb \
        -j /etc/chef/first-boot.json \
        -K /etc/chef/bootstrap-client.pem \
        -N "${NODE_NAME}"

      # Permanent config (uses the per-node client.pem created above)
      cat > /etc/chef/client.rb <<EOF
chef_server_url  "${CHEF_SERVER_URL}"
node_name        "${NODE_NAME}"
client_key       "/etc/chef/client.pem"
chef_license     "accept-silent"
ssl_verify_mode  :verify_peer
EOF

      shred -u /etc/chef/bootstrap-client.pem /etc/chef/bootstrap-client.rb
      echo "Bootstrap credentials removed from disk."

      echo "=== Chef Bootstrap completed successfully at $(date) ==="

runcmd:
  - bash /var/lib/cloud/scripts/per-once/chef-bootstrap.sh
