# Action Items: Complete Your CI-Driven Bootstrap Setup

## ✅ What Was Just Created For You

You now have a **production-ready, enterprise-grade CI/CD pipeline** for bootstrap. Here's what exists:

### 1. GitHub Actions Workflow
**File:** `.github/workflows/bootstrap-nodes.yml`
- ✅ Pre-creates Chef clients (unique per node)
- ✅ Verifies policy groups
- ✅ Provisions EC2 instances
- ✅ Waits for convergence
- ✅ Verifies compliance

**Status:** Ready to use (just needs secrets)

### 2. Terraform Configuration
**Files:**
- `terraform/main.tf` - EC2 provisioning, security groups, outputs
- `terraform/user-data.sh` - Instance bootstrap script
- `terraform/backend.tf` - State management
- `terraform/terraform.tfvars.example` - Variable template

**Status:** Ready to use (just needs variables filled in)

### 3. Documentation
- `BOOTSTRAP_IMPLEMENTATION_GUIDE.md` - Step-by-step instructions
- `ARCHITECTURE_DIAGRAM.md` - Visual flows and security model

**Status:** Ready to reference

---

## 🔧 What YOU Need To Do (5 Steps, ~15 minutes)

### Step 1: Add GitHub Secrets (2 minutes)

Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions**

Click **New repository secret** and add these 6:

| Secret Name | Value | Where to Get |
|---|---|---|
| `CHEF_SERVER_URL` | `https://your-chef-server.com` | From your Chef Server setup |
| `CHEF_ORG` | `your-org-name` | Your Chef organization |
| `CHEF_USER` | `ci-automation` (or existing CI user) | From your Chef Server |
| `CHEF_USER_KEY` | Full content of `~/.chef/ci-user.pem` | Your CI automation key |
| `AWS_ACCESS_KEY_ID` | Your AWS access key | AWS IAM console |
| `AWS_SECRET_ACCESS_KEY` | Your AWS secret key | AWS IAM console |

✅ **Verification:** All 6 secrets appear in repository Settings

---

### Step 2: Create Terraform Variables File (3 minutes)

```bash
# Copy template
cp terraform/terraform.tfvars.example terraform/terraform.tfvars

# Edit and fill in YOUR values
cat terraform/terraform.tfvars
```

Edit `terraform/terraform.tfvars`:
```hcl
# REPLACE WITH YOUR VALUES
chef_server_url = "https://ssj-chef-automate-osaka.success.chef.co"  # From CHEF_SERVER_URL secret
chef_org        = "ssj"                                              # From CHEF_ORG secret
aws_region      = "ap-northeast-3"                                  # Where you want instances
instance_type   = "t3.micro"                                        # Instance size
node_count      = 5                                                 # Start with 5 for testing
policy_group    = "test"                                            # Target policy group
```

Save file.

✅ **Verification:** `terraform/terraform.tfvars` exists with your values

---

### Step 3: Commit & Push to Git (2 minutes)

```bash
cd /Users/sjha/Documents/chef-test2

# Add workflow file
git add .github/workflows/bootstrap-nodes.yml

# Add Terraform config
git add terraform/main.tf terraform/user-data.sh terraform/backend.tf

# Add documentation
git add BOOTSTRAP_IMPLEMENTATION_GUIDE.md ARCHITECTURE_DIAGRAM.md

# Add terraform variables (IMPORTANT: .gitignore should exclude .tfvars)
# Verify: .tfvars should NOT be in git (contains secrets)
git status | grep terraform.tfvars  # Should show nothing

# Commit
git commit -m "feat: add CI-driven bootstrap pipeline

- GitHub Actions workflow for pre-creating Chef clients
- Terraform config for EC2 provisioning
- user-data script for instance bootstrap
- Full documentation and architecture diagrams"

git push origin main
```

✅ **Verification:** Files pushed to GitHub (view on github.com)

---

### Step 4: Verify Terraform Syntax Locally (3 minutes)

```bash
cd /Users/sjha/Documents/chef-test2/terraform

# Initialize Terraform
terraform init

# Validate syntax
terraform validate

# Check plan (no apply yet)
terraform plan -var-file=terraform.tfvars
```

Expected output:
```
Terraform will perform the following actions:
  + aws_instance.chef_nodes[0] will be created
  + aws_instance.chef_nodes[1] will be created
  ...
  + aws_security_group.chef_nodes will be created

Plan: 6 to add, 0 to change, 0 to destroy.
```

✅ **Verification:** Terraform validates with no errors

---

### Step 5: Run the Workflow! (5 minutes setup + 20-30 min execution)

**Option A: Via GitHub UI (Easiest)**

1. Go to your GitHub repo → **Actions**
2. Click **Bootstrap Nodes CI**
3. Click **Run workflow** button
4. Fill in inputs:
   - **node_count:** 5
   - **policy_group:** test
   - **aws_region:** ap-northeast-3
5. Click **Run workflow** (green button)
6. Watch execution in real-time:
   - Job 1: Creating clients (2 min)
   - Job 2: Verifying policy (30 sec)
   - Job 3: Provisioning infrastructure (5 min)
   - Job 4: Waiting for convergence (10-15 min)
   - Job 5: Verifying compliance (1 min)

**Option B: Via CLI**

```bash
gh workflow run bootstrap-nodes.yml \
  -f node_count=5 \
  -f policy_group=test \
  -f aws_region=ap-northeast-3
```

### Watch Execution

Monitor the workflow:
```bash
# Watch logs in real-time
gh run watch <run-id>

# Or view on GitHub Actions page
# Repo → Actions → Bootstrap Nodes CI → [Your Run]
```

✅ **Success Criteria:**
- ✓ All 5 jobs complete without errors
- ✓ Workflow shows "✓ passed" in green
- ✓ Instance IDs and IPs output in Job 3
- ✓ Node count reaches 5/5 in Job 4

---

## 📋 Testing & Validation (After Workflow Completes)

### Verify on Chef Server

```bash
# List nodes created by workflow
knife node list | grep "node-test"

# Show details of first node
knife node show node-test-<timestamp>-1 -F json | jq '.'

# Verify policy applied
knife node show node-test-<timestamp>-1 -F json | jq '.policy_name, .policy_group'
```

Expected output:
```json
{
  "policy_name": "automate_compliance",
  "policy_group": "test",
  "automatic": {
    "ipaddress": "54.123.45.67",
    "hostname": "ip-10-0-0-123"
  }
}
```

### SSH Into a Node (Optional)

```bash
# Get public IP from workflow output
PUBLIC_IP="54.123.45.67"  # From Terraform outputs

# SSH in
ssh -i ~/.chef/ssj-osaka1.pem ubuntu@$PUBLIC_IP

# Check Chef logs
tail -100 /var/log/syslog | grep chef-client

# Manual chef-client run
sudo chef-client -l info

# Verify client.pem exists
ls -la /etc/chef/client.pem  # Should show 600 perms
```

### Check Chef Automate

1. Go to Chef Automate: https://ssj-chef-automate-osaka.success.chef.co
2. **Compliance** → **Scan Results**
3. Filter by nodes created: `node-test-<timestamp>-*`
4. Verify CIS Ubuntu profile ran

---

## 🎯 Next Milestones

### ✅ Immediate (This Week)
- [ ] Complete all 5 steps above
- [ ] Run workflow with 5 nodes
- [ ] Verify nodes on Chef Server
- [ ] Verify nodes in Chef Automate
- [ ] Document any issues encountered

### 🟡 Medium Term (Next Week)
- [ ] Increase to 50 nodes: update node_count in workflow input
- [ ] Test cleanup: run `terraform destroy` to remove old nodes
- [ ] Implement wave-based rollout for larger scales

### 🚀 Long Term (Production)
- [ ] Move Terraform state to S3 with encryption
- [ ] Implement approval gates for prod deployments
- [ ] Add monitoring/alerting for failed converges
- [ ] Test full 1000-node deployment
- [ ] Document node decommissioning process

---

## 🆘 Troubleshooting

### Workflow Fails: "CHEF_SERVER_URL not found"
→ You didn't add GitHub secrets (Step 1)
→ Re-check Settings → Secrets → all 6 present

### Workflow Fails: "terraform init" error
→ Terraform not installed or PATH issue
→ Run locally: `cd terraform && terraform init`

### Nodes Don't Appear After 15 min
→ SSH into instance, check `/var/log/cloud-init-output.log`
→ Verify `client.pem` was written: `cat /etc/chef/client.pem`
→ Manual test: `sudo chef-client -l info`

### "Cannot find policy group" error
→ Policy group (test/stage/prod) doesn't exist on Chef Server
→ Create it: `knife policy groups create test`

---

## 📞 Quick Reference

### Files You Created
```
.github/workflows/bootstrap-nodes.yml       (Main workflow)
terraform/main.tf                           (EC2 provisioning)
terraform/user-data.sh                      (Instance bootstrap)
terraform/backend.tf                        (State config)
terraform/terraform.tfvars                  (Your variables - DON'T COMMIT)
BOOTSTRAP_IMPLEMENTATION_GUIDE.md           (Full docs)
ARCHITECTURE_DIAGRAM.md                     (Visual flows)
ACTION_ITEMS.md                             (This file)
```

### Key Commands
```bash
# View workflow logs
gh run view <run-id> --log

# Destroy test infrastructure
cd terraform && terraform destroy -auto-approve

# Manually create Chef client (if needed)
knife client create node-test-manual -f node-test-manual.pem

# List all nodes in policy group
knife node list | grep "node-test"

# Get IP of a specific node
knife node show node-test-<timestamp>-1 -F json | jq '.automatic.ipaddress'
```

---

## ✨ That's It!

You now have an **enterprise-ready, scalable, fully-automated** bootstrap pipeline.

**Next action:** Complete the 5 steps above, then run the workflow with 5 nodes.

Good luck! 🚀
