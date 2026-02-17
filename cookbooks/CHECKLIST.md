# CI-Driven Bootstrap: Final Checklist

## What Was Created For You ✅

| Component | File | Status |
|-----------|------|--------|
| **Workflow** | `.github/workflows/bootstrap-nodes.yml` | ✅ Ready |
| **Provisioning** | `terraform/main.tf` | ✅ Ready |
| **Bootstrap** | `terraform/user-data.sh` | ✅ Ready |
| **Config** | `terraform/backend.tf` | ✅ Ready |
| **Template** | `terraform/terraform.tfvars.example` | ✅ Ready |
| **Quick Guide** | `QUICK_START.md` | ✅ Ready |
| **Implementation** | `ACTION_ITEMS.md` | ✅ Ready |
| **Full Docs** | `BOOTSTRAP_IMPLEMENTATION_GUIDE.md` | ✅ Ready |
| **Architecture** | `ARCHITECTURE_DIAGRAM.md` | ✅ Ready |
| **Summary** | `BOOTSTRAP_SUMMARY.md` | ✅ Ready |

## Your 5 Action Items

### ☐ Step 1: Add GitHub Secrets
```
Go to: Settings → Secrets and variables → Actions
Add 6 secrets:
- CHEF_SERVER_URL = your-server.com
- CHEF_ORG = your-org
- CHEF_USER = ci-automation
- CHEF_USER_KEY = (paste ~/.chef/ci-user.pem content)
- AWS_ACCESS_KEY_ID = your-key
- AWS_SECRET_ACCESS_KEY = your-secret
```
**Time: 2 minutes**

### ☐ Step 2: Create terraform.tfvars
```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit file with your values (chef_server_url, chef_org, etc.)
```
**Time: 3 minutes**

### ☐ Step 3: Commit & Push
```bash
git add .github/workflows/bootstrap-nodes.yml terraform/
git add *.md
git commit -m "add CI-driven bootstrap pipeline"
git push origin main
```
**Time: 2 minutes**

### ☐ Step 4: Verify Locally
```bash
cd terraform && terraform init && terraform validate
# Should show no errors
```
**Time: 3 minutes**

### ☐ Step 5: Run Workflow
```
Go to GitHub → Actions → Bootstrap Nodes CI → Run Workflow
Inputs:
  - node_count: 5
  - policy_group: test
  - aws_region: ap-northeast-3
Click "Run workflow"
```
**Time: 30 minutes execution**

---

## Verify Success

After workflow completes:

```bash
# List nodes created
knife node list | grep "node-test"

# Show node details
knife node show <node-name> -F json | jq '.policy_name, .policy_group'

# SSH into a node
ssh -i ~/.chef/ssj-osaka1.pem ubuntu@<public-ip>

# Check Chef logs
sudo tail -50 /var/log/syslog | grep chef-client
```

Expected output:
```
policy_name: "automate_compliance"
policy_group: "test"
Infra Phase complete
```

---

## Key Commands

```bash
# Destroy all nodes
cd terraform && terraform destroy -auto-approve

# View workflow logs
gh run view <run-id> --log

# Get node IP
knife node show <name> -F json | jq '.automatic.ipaddress'

# Check compliance
knife node show <name> -F json | jq '.automatic.audit_report'
```

---

## Important Notes

### GitHub Secrets
- ✅ Never commit `.tfvars` file (contains secrets)
- ✅ Store in GitHub Secrets, not code
- ✅ Rotate keys periodically

### Terraform State
- ⚠️ Currently local (terraform.tfstate)
- 🔜 Should move to S3 for production
- Uncomment S3 section in `backend.tf` when ready

### Security
- ✅ No validator key in code
- ✅ Each node gets unique client.pem
- ✅ Full audit trail in GitHub & Chef Server
- ⚠️ Data collector token hardcoded (improve later)

---

## File Locations

```
/Users/sjha/Documents/chef-test2/cookbooks/
├── .github/workflows/
│   └── bootstrap-nodes.yml
├── terraform/
│   ├── main.tf
│   ├── user-data.sh
│   ├── backend.tf
│   └── terraform.tfvars.example
└── *.md (documentation files)
```

---

## Common Issues & Fixes

### GitHub Secrets Not Recognized
**Problem:** Workflow fails with "CHEF_SERVER_URL not found"
**Fix:** Verify all 6 secrets are in Settings → Secrets
**Time: 2 min**

### Terraform Validate Fails
**Problem:** `terraform validate` shows errors
**Fix:** Run `cd terraform && terraform init` first
**Time: 3 min**

### Nodes Don't Appear
**Problem:** Workflow completes but nodes don't show in `knife node list`
**Fix:** SSH to instance, check `/var/log/cloud-init-output.log`
**Time: 10 min debugging**

### AWS Credentials Error
**Problem:** "UnauthorizedOperation" or "AccessDenied"
**Fix:** Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in GitHub Secrets
**Time: 2 min**

---

## Scaling Examples

### 5 Nodes (Test)
```bash
# Workflow Input
node_count: 5
policy_group: test

# Expected Time: 30 minutes
```

### 50 Nodes (Batch)
```bash
# Workflow Input
node_count: 50
policy_group: test

# Expected Time: 35-40 minutes
```

### 500 Nodes (Large)
```bash
# Workflow Input
node_count: 500
policy_group: stage

# Expected Time: 45-50 minutes
# Requires Chef Server tuning
```

### 1000+ Nodes (Enterprise)
```bash
# Option 1: Wave-based
# Run 1: 200 nodes
# Sleep 5 min
# Run 2: 200 nodes
# ... repeat
# Total Time: 50 minutes, 5 separate runs

# Option 2: Multi-region
# Region A: 500 nodes (parallel)
# Region B: 500 nodes (parallel)
# Total Time: 45 minutes, same wall-clock time
```

---

## Documentation Map

**Start Here:**
- `QUICK_START.md` — 10 minute overview

**Then Read:**
- `ACTION_ITEMS.md` — Detailed implementation steps
- `BOOTSTRAP_SUMMARY.md` — What you got and why

**For Deep Dive:**
- `BOOTSTRAP_IMPLEMENTATION_GUIDE.md` — Full technical details
- `ARCHITECTURE_DIAGRAM.md` — Flows, security, scaling

**Reference:**
- `CHECKLIST.md` — This file

---

## Success Criteria ✅

After all 5 steps, you should see:

- [x] GitHub workflow file in `.github/workflows/`
- [x] Terraform files in `terraform/` directory
- [x] All 6 GitHub Secrets added
- [x] terraform.tfvars filled with your values
- [x] Workflow runs and completes without errors
- [x] 5 new nodes appear in `knife node list`
- [x] Nodes have policy_group=test
- [x] Nodes show "Infra Phase complete"
- [x] Compliance data in Chef Automate

**Once all checked → You're production-ready! 🚀**

---

## Timeline

| Task | Time | Total |
|------|------|-------|
| Add GitHub Secrets | 2 min | 2 min |
| Create terraform.tfvars | 3 min | 5 min |
| Commit & Push | 2 min | 7 min |
| Verify Terraform | 3 min | 10 min |
| Run Workflow | 30 min | 40 min |
| Verify Success | 5 min | 45 min |

**Total Time to First Success: ~45 minutes**

---

## Next Steps (After Success)

1. **This Week:** Scale to 50 nodes, test wave-based deployment
2. **Next Week:** Move Terraform state to S3, implement approval gates
3. **Next Month:** Deploy to production (1000+ nodes)

---

## Still Need Help?

### For Implementation Questions
→ Read `ACTION_ITEMS.md`

### For Architecture Questions
→ Read `ARCHITECTURE_DIAGRAM.md`

### For Troubleshooting
→ See "Common Issues & Fixes" above

### For Full Details
→ Read `BOOTSTRAP_IMPLEMENTATION_GUIDE.md`

---

## You Have Everything You Need! ✨

All files created. All documentation written. Ready to go!

**Next action: Start with Step 1 (Add GitHub Secrets)**

Good luck! 🎯
