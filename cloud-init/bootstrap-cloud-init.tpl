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

      # ── Variables replaced at launch time ─────────────────────────────────
      CHEF_SERVER_URL="__CHEF_SERVER_URL__"
      NODE_NAME="__NODE_NAME__"
      S3_URI="__S3_URI__"
      RUN_LIST='__RUN_LIST__'
      # ──────────────────────────────────────────────────────────────────────

      # Install AWS CLI
      apt-get update -y
      apt-get install -y awscli

      # Install chef-client
      curl -fsSL https://omnitruck.chef.io/install.sh | bash -s -- -P chef -c stable

      mkdir -p /etc/chef
      chmod 700 /etc/chef

      # Fetch bootstrap client key from S3 (instance IAM role must allow s3:GetObject)
      echo "Fetching client key from ${S3_URI}"
      aws s3 cp "${S3_URI}" /etc/chef/client.pem
      chmod 600 /etc/chef/client.pem

      # Write client.rb
      cat > /etc/chef/client.rb <<CLIENTRB
      chef_server_url  "${CHEF_SERVER_URL}"
      node_name        "${NODE_NAME}"
      client_name      "${NODE_NAME}"
      client_key       "/etc/chef/client.pem"
      chef_license     "accept-silent"
      ssl_verify_mode  :verify_peer
      CLIENTRB

      # Write first-boot.json
      cat > /etc/chef/first-boot.json <<FIRSTBOOT
      {
        "run_list": ${RUN_LIST}
      }
      FIRSTBOOT

      echo "=== Running chef-client ==="
      chef-client -j /etc/chef/first-boot.json

      echo "=== Chef Bootstrap completed successfully at $(date) ==="

runcmd:
  - bash /var/lib/cloud/scripts/per-once/chef-bootstrap.sh
