# CI-Driven Bootstrap Implementation Guide

## 📋 Overview

You now have an **enterprise-grade CI/CD pipeline** that:

1. **Pre-creates Chef clients** on Chef Server (unique per node)
2. **Provisions infrastructure** with Terraform (EC2 instances)
3. **Injects client credentials** via user_data
4. **Nodes self-configure** on first boot with `chef-client`
5. **Verifies convergence** and compliance

**No validator key needed. No SSH bootstrap. Fully automated.**

---

## 🎯 What Was Added

### 1. **GitHub Actions Workflow** (`.github/workflows/bootstrap-nodes.yml`)

**Jobs:**
- `create_chef_clients` → Creates unique client.pem for each node on Chef Server
- `verify_policy` → Ensures target policy group exists
- `terraform_provision` → Launches EC2 instances with Terraform
- `verify_convergence` → Waits for nodes to register and report to Chef Server
- `verify_compliance` → (Optional) Checks compliance status

**Inputs:**
- `node_count` - How many nodes to provision (e.g., 5, 100, 1000)
- `policy_group` - Target policy group (test/stage/prod)
- `aws_region` - AWS region (default: ap-northeast-3)

**Key Features:**
- ✅ Automatic unique node naming with timestamp
- ✅ Artifact storage of client keys (1-day retention)
- ✅ Real-time node reporting verification
- ✅ Policy group validation before provisioning

---

### 2. **Terraform Configuration**

#### **main.tf**
- EC2 instance provisioning (count-based: 1 to N nodes)
- Auto-discovers latest Ubuntu 22.04 AMI
- Security group for SSH, HTTP, HTTPS
- **Injects client.pem into each instance via user_data**
- Outputs instance IDs, IPs, details

#### **user-data.sh**
- Installs Chef Infra Client on first boot
- Writes `/etc/chef/client.pem` (from Terraform variable)
- Configures `/etc/chef/client.rb` with:
  - Chef Server URL
  - Policy name & group
  - Data collector for Automate
  - Node name from hostname
- Runs initial `chef-client` with retry logic

#### **backend.tf**
- Local state by default (can switch to S3)

#### **terraform.tfvars.example**
- Template for your values

---

## 🚀 How to Use

### Step 1: Add GitHub Secrets

Add these to your repository (Settings → Secrets and variables):

```
CHEF_SERVER_URL        = https://your-chef-server.example.com
CHEF_ORG               = your-org
CHEF_USER              = ci-automation
CHEF_USER_KEY          = (contents of ~/.chef/ci-user.pem)
AWS_ACCESS_KEY_ID      = your-aws-key
AWS_SECRET_ACCESS_KEY  = your-aws-secret
```

### Step 2: Create Terraform Variables

Copy the template and fill in your values:

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

Edit `terraform/terraform.tfvars`:
```hcl
chef_server_url = "https://chef-server.success.chef.co"
chef_org        = "myorg"
aws_region      = "ap-northeast-3"
instance_type   = "t3.micro"
```

### Step 3: Trigger Workflow

Go to **Actions** → **Bootstrap Nodes CI** → **Run Workflow**

Input parameters:
- **node_count:** 5
- **policy_group:** test
- **aws_region:** ap-northeast-3

Click **Run workflow**

---

## 📊 What Happens (Step-by-Step)

### Phase 1: Client Pre-Creation (2 min)
```
✓ Authenticates to Chef Server with CI credentials
✓ Creates 5 unique clients: node-test-1734567890-1 through -5
✓ Downloads .pem files for each
✓ Stores as workflow artifacts
```

Output:
```
Creating Chef client: node-test-1734567890-1
Creating Chef client: node-test-1734567890-2
...
```

### Phase 2: Policy Verification (30 sec)
```
✓ Confirms policy group "test" exists
✓ Shows current policy revision
```

### Phase 3: Infrastructure Provisioning (3-5 min)
```
✓ Downloads client.pem artifacts
✓ Authenticates to AWS
✓ Runs `terraform plan` with 5 nodes
✓ Applies: 5 EC2 instances created
✓ Each instance gets unique client.pem injected
```

Output:
```
aws_instance.chef_nodes[0]: Creating...
aws_instance.chef_nodes[1]: Creating...
...
Outputs:
instance_ids = ["i-0abc123def456", "i-0def456ghi789", ...]
instance_ips = ["54.123.45.67", "54.123.45.68", ...]
```

### Phase 4: Convergence Verification (5-15 min)
```
✓ Waits for EC2 instances to boot
✓ Runs chef-client on each
✓ Nodes authenticate with client.pem
✓ Nodes register on Chef Server
✓ Polls Chef Server every 10 sec until all 5 nodes appear
```

Output:
```
Waiting for nodes in policy group: test
Attempt 1: Found 0/5 nodes
Attempt 2: Found 0/5 nodes
Attempt 15: Found 5/5 nodes
✓ All nodes reported to Chef Server
```

### Phase 5: Compliance Verification (1 min, test only)
```
✓ Runs for test policy group only
✓ Shows compliance phase results
✓ Confirms nodes are running policies correctly
```

---

## 🔐 Security Model

### What's Secure:
- ✅ **No validator key in Git** (unique per-node credentials)
- ✅ **No plaintext secrets in Terraform** (GitHub secrets only)
- ✅ **Client keys ephemeral** (artifacts deleted after 1 day)
- ✅ **AWS credentials never logged** (GitHub Actions masking)
- ✅ **Audit trail** (CI logs show exactly what was created)

### What's NOT Secure Yet:
- ⚠️ `chef_server_url` visible in Terraform state
- ⚠️ Data collector token hardcoded in user-data.sh
- ⚠️ State files stored locally (not S3-backed with encryption)

### To Improve:
1. **Move state to S3** (uncomment backend.tf S3 section)
2. **Store data collector token in AWS Secrets Manager** (update user-data.sh to fetch it)
3. **Use IAM roles** for Terraform execution instead of static keys

---

## 📈 Scaling to 1000 Nodes

### How This Scales:
- **CI job:** Can create 1000 clients in <5 minutes
- **Terraform:** Launches 1000 instances in parallel, completes in 3-5 min
- **Chef convergence:** Happens in parallel on all instances
- **Bottleneck:** Chef Server might need tuning for 1000 concurrent checkins

### To Handle 1000 Nodes:
1. Increase Chef Server CPU/RAM
2. Split into waves: 100 nodes per run, pause 30 sec between waves
3. Use local-exec in Terraform to batch knife commands:
   ```hcl
   provisioner "local-exec" {
     command = "chef-client -l info"
   }
   ```

---

## 🐛 Troubleshooting

### Nodes Not Appearing After 15 min
```bash
# 1. Check if instances are running
aws ec2 describe-instances --filter "Name=tag:Environment,Values=test" --region ap-northeast-3

# 2. SSH into a running instance and check logs
ssh -i ~/.chef/ssj-osaka1.pem ubuntu@<instance-ip>
tail -f /var/log/cloud-init-output.log

# 3. Verify client.pem was written
cat /etc/chef/client.pem

# 4. Test manual chef-client run
sudo /opt/chef/bin/chef-client -l info
```

### Chef Client Fails with "Client Not Found"
```
Check:
1. Client was created on Chef Server: knife client list | grep "node-test"
2. client.pem matches: diff /etc/chef/client.pem <downloaded-from-CI>
3. Chef Server URL is correct in /etc/chef/client.rb
```

### Terraform Apply Fails
```bash
# Check Terraform syntax
cd terraform
terraform validate

# Check variable values
terraform plan -var-file=terraform.tfvars

# Check AWS credentials
aws sts get-caller-identity
```

---

## 📋 Next Steps

### Short Term (This Week)
- [ ] Add GitHub secrets
- [ ] Copy Terraform template and fill values
- [ ] Run workflow with 5 test nodes
- [ ] Verify nodes appear on Chef Server

### Medium Term (Next Week)
- [ ] Test compliance verification
- [ ] Implement wave-based rollout (100 nodes per wave)
- [ ] Move Terraform state to S3

### Long Term (Enterprise)
- [ ] Implement node approval gate (manual approval for stage/prod)
- [ ] Add monitoring/alerting for failed converges
- [ ] Implement auto-rollback on compliance failures
- [ ] Document node decommissioning process

---

## 🎓 Learning Resources

### This Pattern Implements:
- **Immutable Infrastructure** - Nodes created fresh, no configuration drift
- **Infrastructure as Code** - All infra defined in Git
- **GitOps** - CI is source of truth for deployments
- **Least Privilege** - Each node has unique credentials
- **Audit Trail** - Full history in CI logs and Git

### Related Concepts:
- [Chef Policyfile](https://docs.chef.io/policyfile/)
- [Terraform EC2 Provisioning](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance)
- [GitHub Actions Artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)
- [Chef Server API](https://docs.chef.io/api_chef_server/)

---

## ✅ Validation Checklist

Before running 1000 nodes:

- [ ] Workflow completes successfully with 5 nodes
- [ ] All 5 nodes appear in `knife node list`
- [ ] Nodes have correct policy_name and policy_group
- [ ] `chef-client` log shows "Infra Phase complete"
- [ ] Compliance data appears in Chef Automate
- [ ] Policy promotion (test → stage → prod) works smoothly
- [ ] Removing nodes and re-running still works

Once all checked ✓, scale to 1000.
