#cloud-config
package_update: true

runcmd:
  - set -euo pipefail
  - |
    # Variables to replace (or use cloud-provider templating / user-data rendering)
    CHEF_SERVER_URL="__CHEF_SERVER_URL__"
    NODE_NAME="__NODE_NAME__"
    S3_URI="__S3_URI__"    # e.g. s3://bucket/path/bootstrap-client.pem
    RUN_LIST='__RUN_LIST__' # e.g. ["recipe[sample_nginx::default]"]

    # Install awscli and chef-client
    curl -L https://omnitruck.chef.io/install.sh | bash -s -- -P chef -c stable
    apt-get update -y && apt-get install -y awscli

    mkdir -p /etc/chef
    chmod 700 /etc/chef

    # Fetch client key from S3 (instance must have IAM role with read access)
    if [ -n "$S3_URI" ]; then
      echo "Fetching client key from $S3_URI"
      aws s3 cp "$S3_URI" /etc/chef/client.pem
      chmod 600 /etc/chef/client.pem
    else
      echo "ERROR: S3_URI not provided"
      exit 1
    fi

    # Write client.rb
    cat > /etc/chef/client.rb <<EOF
    chef_server_url  "$CHEF_SERVER_URL"
    node_name        "$NODE_NAME"
    chef_license     "accept-silent"
    EOF

    # Write first-boot.json
    cat > /etc/chef/first-boot.json <<EOF
    {
      "run_list": $RUN_LIST
    }
    EOF

    # Run chef-client once
    chef-client -j /etc/chef/first-boot.json --once

# End of template
