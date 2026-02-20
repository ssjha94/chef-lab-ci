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
      KNIFE=/opt/chef/bin/knife
      # ──────────────────────────────────────────────────────────────────────

      # Install AWS CLI + chef (knife is bundled at /opt/chef/bin/knife)
      apt-get update -y
      apt-get install -y awscli
      curl -fsSL https://omnitruck.chef.io/install.sh | bash -s -- -P chef -c stable

      mkdir -p /etc/chef
      chmod 700 /etc/chef

      # ── Phase 1: Fetch bootstrap key and write a Phase-1 client.rb ────────
      # bootstrap-client is the shared identity that owns the S3 key.
      # It has ACLs on the clients + nodes containers on Chef Server.
      echo "Fetching bootstrap client key from ${S3_URI}"
      aws s3 cp "${S3_URI}" /etc/chef/bootstrap.pem
      chmod 600 /etc/chef/bootstrap.pem

      printf 'chef_server_url  "%s"\nnode_name        "bootstrap-client"\nclient_key       "/etc/chef/bootstrap.pem"\nchef_license     "accept-silent"\nssl_verify_mode  :verify_peer\n' \
        "${CHEF_SERVER_URL}" > /etc/chef/bootstrap-client.rb

      # ── Phase 2: Create a real per-node client + key on Chef Server ───────
      # Use bootstrap-client credentials to mint a new client named ${NODE_NAME}
      # and save its private key to /etc/chef/client.pem.
      echo "Creating per-node client '${NODE_NAME}' on Chef Server..."
      if ! $KNIFE client create "${NODE_NAME}" \
          --config /etc/chef/bootstrap-client.rb \
          --disable-editing \
          --file /etc/chef/client.pem; then
        # Client may exist from a previous attempt — reregister to get a fresh key
        echo "Client already exists — reregistering to refresh key..."
        $KNIFE client reregister "${NODE_NAME}" \
          --config /etc/chef/bootstrap-client.rb \
          --file /etc/chef/client.pem
      fi
      chmod 600 /etc/chef/client.pem
      echo "Per-node key for '${NODE_NAME}' saved to /etc/chef/client.pem"

      # ── Phase 3: Switch to per-node identity ──────────────────────────────
      # Now that ${NODE_NAME} has its own client + key, make it the permanent identity.
      printf 'chef_server_url  "%s"\nnode_name        "%s"\nclient_key       "/etc/chef/client.pem"\nchef_license     "accept-silent"\nssl_verify_mode  :verify_peer\n' \
        "${CHEF_SERVER_URL}" "${NODE_NAME}" > /etc/chef/client.rb

      # Shred bootstrap key — no longer needed on this node
      shred -u /etc/chef/bootstrap.pem /etc/chef/bootstrap-client.rb
      echo "Bootstrap credentials removed from disk."

      # Write first-boot.json
      printf '{\n  "run_list": %s\n}\n' "${RUN_LIST}" > /etc/chef/first-boot.json

      # ── Phase 4: Run chef-client as the real node ─────────────────────────
      echo "=== Running chef-client as '${NODE_NAME}' ==="
      chef-client -j /etc/chef/first-boot.json

      echo "=== Chef Bootstrap completed successfully at $(date) ==="

runcmd:
  - bash /var/lib/cloud/scripts/per-once/chef-bootstrap.sh
