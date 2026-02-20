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

      # Write client.rb — authenticate as bootstrap-client (owner of the S3 key)
      # node_name is passed via --node-name flag at runtime so Chef Server
      # creates the node object under the correct name
      printf 'chef_server_url  "%s"\nclient_name      "bootstrap-client"\nclient_key       "/etc/chef/client.pem"\nchef_license     "accept-silent"\nssl_verify_mode  :verify_peer\n' \
        "${CHEF_SERVER_URL}" > /etc/chef/client.rb

      # Write first-boot.json — use printf to avoid heredoc indentation issues
      printf '{\n  "run_list": %s\n}\n' "${RUN_LIST}" > /etc/chef/first-boot.json

      echo "=== Running chef-client ==="
      # --node-name overrides node identity for the node object on Chef Server
      # while client_name in client.rb handles authentication as bootstrap-client
      chef-client --node-name "${NODE_NAME}" -j /etc/chef/first-boot.json

      echo "=== Chef Bootstrap completed successfully at $(date) ==="

runcmd:
  - bash /var/lib/cloud/scripts/per-once/chef-bootstrap.sh
