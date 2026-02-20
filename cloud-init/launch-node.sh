#!/usr/bin/env bash
# launch-node.sh — Launch an EC2 instance and bootstrap it via cloud-init + Chef
# Usage: ./launch-node.sh <node-name> [run-list]
# Example: ./launch-node.sh web-node3 'recipe[sample_nginx::default]'
set -euo pipefail

# ── Configuration (edit these if needed) ─────────────────────────────────────
REGION="ap-northeast-3"
AMI="ami-0da8d411ad1002a94"               # Ubuntu 22.04 (same as test1_linux)
INSTANCE_TYPE="t3.micro"
SUBNET="subnet-04807cdad65de46b5"
SECURITY_GROUP="sg-02f67ae5a44da9476"
KEY_NAME="ssj-osaka1"
IAM_PROFILE="chef-bootstrap-node-profile"
CHEF_SERVER_URL="https://ssj-chef-automate-osaka.success.chef.co/organizations/aws_org"
S3_URI="s3://chef-bootstrap-keys-446539779517/bootstrap/bootstrap-client.pem"
PROFILE="saml"
TEMPLATE_FILE="$(dirname "$0")/bootstrap-cloud-init.tpl"
# ─────────────────────────────────────────────────────────────────────────────

NODE_NAME="${1:-}"
RUN_LIST="${2:-recipe[sample_nginx::default]}"

if [[ -z "$NODE_NAME" ]]; then
  echo "ERROR: node name is required" >&2
  echo "Usage: $0 <node-name> [run-list]" >&2
  exit 1
fi

echo "==> Rendering cloud-init for node: $NODE_NAME"

# Render template — replace all placeholders
USER_DATA=$(sed \
  -e "s|__CHEF_SERVER_URL__|${CHEF_SERVER_URL}|g" \
  -e "s|__NODE_NAME__|${NODE_NAME}|g" \
  -e "s|__S3_URI__|${S3_URI}|g" \
  -e "s|__RUN_LIST__|[\"${RUN_LIST}\"]|g" \
  "$TEMPLATE_FILE")

USERDATA_FILE=$(mktemp /tmp/cloud-init-XXXXXX)
USERDATA_FILE="${USERDATA_FILE}.yaml"
echo "$USER_DATA" > "$USERDATA_FILE"
echo "==> cloud-init written to: $USERDATA_FILE"

echo "==> Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
  --region "$REGION" \
  --profile "$PROFILE" \
  --image-id "$AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --subnet-id "$SUBNET" \
  --security-group-ids "$SECURITY_GROUP" \
  --key-name "$KEY_NAME" \
  --associate-public-ip-address \
  --iam-instance-profile Name="$IAM_PROFILE" \
  --user-data "file://$USERDATA_FILE" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${NODE_NAME}},{Key=ChefNode,Value=true}]" \
  --query 'Instances[0].InstanceId' \
  --output text)

rm -f "$USERDATA_FILE"

echo ""
echo "✅ Instance launched: $INSTANCE_ID"
echo "   Node name:  $NODE_NAME"
echo "   Run list:   [$RUN_LIST]"
echo "   Region:     $REGION"
echo ""
echo "==> Waiting for instance to be running..."
aws ec2 wait instance-running \
  --region "$REGION" \
  --profile "$PROFILE" \
  --instance-ids "$INSTANCE_ID"

PUBLIC_IP=$(aws ec2 describe-instances \
  --region "$REGION" \
  --profile "$PROFILE" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

echo ""
echo "✅ Instance is running"
echo "   Instance ID: $INSTANCE_ID"
echo "   Public IP:   $PUBLIC_IP"
echo ""
echo "==> cloud-init is now running on the instance."
echo "    Chef bootstrap will complete in ~3-5 minutes."
echo ""
echo "To check bootstrap progress (SSH in after ~1 min):"
echo "  ssh -i ~/.ssh/ssj-osaka1.pem ubuntu@$PUBLIC_IP"
echo "  sudo tail -f /var/log/cloud-init-output.log"
echo ""
echo "To verify node registered with Chef Server:"
echo "  knife node show $NODE_NAME"
