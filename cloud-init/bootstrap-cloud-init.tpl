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

        # Install AWS CLI + Chef Infra Client
        apt-get update -y
        apt-get install -y awscli
        curl -fsSL https://omnitruck.chef.io/install.sh | bash -s -- -P chef -c stable

        mkdir -p /etc/chef
        chmod 700 /etc/chef

        # Fetch bootstrap client key from S3 (bootstrap-client has create ACLs)
        echo "Fetching bootstrap client key from ${S3_URI}"
        aws s3 cp "${S3_URI}" /etc/chef/bootstrap-client.pem
        chmod 600 /etc/chef/bootstrap-client.pem

        # Write a temporary config that uses the bootstrap key for validation
        printf 'chef_server_url          "%s"\nnode_name                "%s"\nclient_key               "/etc/chef/client.pem"\nvalidation_client_name   "bootstrap-client"\nvalidation_key           "/etc/chef/bootstrap-client.pem"\nchef_license             "accept-silent"\nssl_verify_mode          :verify_peer\n' \\
          "${CHEF_SERVER_URL}" "${NODE_NAME}" > /etc/chef/bootstrap-client.rb

        # Write first-boot.json
        printf '{\n  "run_list": %s\n}\n' "${RUN_LIST}" > /etc/chef/first-boot.json

        # First run: chef-client will create client[node_name] using the bootstrap key
        echo "=== Running chef-client (validator-less via -K) as '${NODE_NAME}' ==="
        chef-client \
          -c /etc/chef/bootstrap-client.rb \
          -j /etc/chef/first-boot.json \
          -K /etc/chef/bootstrap-client.pem \
          -N "${NODE_NAME}"

        # Replace client.rb with the permanent per-node identity (no validation key)
        printf 'chef_server_url  "%s"\nnode_name        "%s"\nclient_key       "/etc/chef/client.pem"\nchef_license     "accept-silent"\nssl_verify_mode  :verify_peer\n' \\
          "${CHEF_SERVER_URL}" "${NODE_NAME}" > /etc/chef/client.rb

        # Shred bootstrap key and temp config
        shred -u /etc/chef/bootstrap-client.pem /etc/chef/bootstrap-client.rb
        echo "Bootstrap credentials removed from disk."

        echo "=== Chef Bootstrap completed successfully at $(date) ==="

runcmd:
  - bash /var/lib/cloud/scripts/per-once/chef-bootstrap.sh
