# Enterprise Bootstrap Architecture

## 🎯 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Actions Workflow                     │
│                   (bootstrap-nodes.yml)                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────┴─────────────────────────┐
    ↓                                                   ↓
┌──────────────────────┐                    ┌──────────────────────┐
│  Chef Server API     │                    │    AWS EC2 API       │
│  ├─ Create clients   │                    │  ├─ Launch instances │
│  ├─ Download .pem    │                    │  ├─ Assign SGs       │
│  └─ List clients     │                    │  └─ Configure tags   │
└──────────────────────┘                    └──────────────────────┘
         ↓                                          ↓
    ┌─────────────────────────────────────────────────────────────┐
    │           Workflow Artifacts                                │
    │  ├─ node-test-1234567890-1.pem                              │
    │  ├─ node-test-1234567890-2.pem                              │
    │  └─ ... (one per node)                                      │
    └─────────────────────────────────────────────────────────────┘
         ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Terraform Provisioning                                     │
    │  ├─ Download .pem artifacts                                 │
    │  ├─ For each instance:                                      │
    │  │   ├─ Inject client.pem into user_data                    │
    │  │   ├─ Base64 encode with Chef config                      │
    │  │   └─ Pass to EC2 instance                                │
    │  └─ Launch N instances in parallel                          │
    └─────────────────────────────────────────────────────────────┘
         ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  EC2 Instance User-Data Bootstrap (per instance)            │
    │  ├─ 1. Install Chef Infra Client                            │
    │  ├─ 2. Write /etc/chef/client.pem (from user_data)          │
    │  ├─ 3. Write /etc/chef/client.rb                            │
    │  ├─ 4. Run: sudo chef-client -l info                        │
    │  └─ 5. (Optional) Delete client.pem                         │
    └─────────────────────────────────────────────────────────────┘
         ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Node Registration (Chef Client)                            │
    │  ├─ Connect to Chef Server using client.pem                 │
    │  ├─ Register node in policy_group=test                      │
    │  ├─ Fetch automate_compliance policy                        │
    │  ├─ Run Infra Phase (converge)                              │
    │  ├─ Run Compliance Phase (scan)                             │
    │  ├─ Send data to Automate data-collector                    │
    │  └─ Mark as "converged"                                     │
    └─────────────────────────────────────────────────────────────┘
         ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Workflow Verification                                      │
    │  ├─ Poll Chef Server for nodes                              │
    │  ├─ Wait until all N nodes registered                       │
    │  ├─ Show node list with IP addresses                        │
    │  └─ Verify compliance reports in Automate                   │
    └─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Credentials Flow (Secure)

```
GitHub Actions Secrets
├─ CHEF_SERVER_URL
├─ CHEF_ORG
├─ CHEF_USER
├─ CHEF_USER_KEY (CI automation user)
├─ AWS_ACCESS_KEY_ID
└─ AWS_SECRET_ACCESS_KEY

    ↓ (Step 1: Create clients)

Chef Server
├─ CI user authenticates with CHEF_USER_KEY
├─ Creates: node-test-1234567890-1 through -N
└─ Downloads unique .pem for each

    ↓ (Step 2: Temporary artifacts)

GitHub Artifact Storage
├─ node-test-1234567890-1.pem (1 day retention)
├─ node-test-1234567890-2.pem (1 day retention)
└─ ... (deleted after 24 hours)

    ↓ (Step 3: Inject into instances)

Terraform (base64-encoded user_data)
├─ For each instance i:
│  ├─ Read artifact: node-test-1234567890-i.pem
│  ├─ Embed in user_data (base64)
│  └─ Launch instance

    ↓ (Step 4: Instance bootstrap)

EC2 Instance (on first boot)
├─ Cloud-init decodes user_data
├─ Writes /etc/chef/client.pem (600 perms)
├─ Runs chef-client
│  └─ Uses client.pem to authenticate
└─ (Optional) Delete /etc/chef/client.pem

    ↓ (Step 5: Node converges)

Chef Server
└─ Node registers with unique client.pem
   (no shared secrets ever used)

Chef Automate
└─ Node sends compliance reports
   (via data-collector token, which is OK at scale)
```

---

## ⚡ Execution Timeline

```
Time  │ Step                              │ Duration
──────┼───────────────────────────────────┼──────────────
0:00  │ Workflow triggered                │ instant
0:05  │ Create 5 Chef clients             │ 2 minutes
0:07  │ Verify policy group exists        │ 30 seconds
0:08  │ Terraform plan & apply            │ 3-5 minutes
      │ └─ Instances boot                 │
0:13  │ Poll for convergence              │ 5-15 minutes
      │   └─ chef-client runs on each     │
      │   └─ nodes register               │
0:28  │ Compliance verification (test)    │ 1 minute
0:29  │ ✓ COMPLETE                        │ ~29 minutes
      │   (5 nodes registered & converged)│
```

For 1000 nodes: ~40-50 minutes (parallelism limits chef-client scaling)

---

## 📊 Comparison: Old vs New

### ❌ OLD WAY (Manual)

```
1. Admin creates validator.pem
2. Admin writes bootstrap script
3. Admin SSH loops: for i in {1..1000}
4. Manual knife bootstrap per node
5. Wait hours for convergence
6. Manual troubleshooting
7. No audit trail
```

**Time:** 6-8 hours
**Cost:** $$$$ (manual labor)
**Risk:** High (manual errors)

---

### ✅ NEW WAY (CI-Driven)

```
1. Dev pushes policy
2. CI triggers workflow
3. CI creates clients
4. CI provisions infrastructure
5. Nodes self-configure
6. Automatic verification
7. Full audit trail
```

**Time:** 30-50 minutes
**Cost:** $0 (automation)
**Risk:** Low (repeatable, tested)

---

## 🎓 Key Concepts

### What Makes This Enterprise-Grade?

1. **Immutable Infrastructure**
   - Nodes are created fresh, not modified
   - Configuration in code (policy), not on disk
   - Changes = new nodes, not patches

2. **Infrastructure as Code (IaC)**
   - All infra defined in Git
   - Version controlled
   - Code review before deploy

3. **GitOps**
   - Git is source of truth
   - CI/CD is deployment mechanism
   - No manual `terraform apply` or `knife` commands

4. **Least Privilege**
   - Each node has unique credentials
   - No shared secrets (validator key)
   - Easy to audit and revoke

5. **Automation**
   - Zero manual steps
   - Repeatable, consistent
   - Scales from 5 to 5000 nodes with same process

6. **Audit Trail**
   - GitHub Actions logs show everything
   - Git history shows changes
   - Chef Server shows registration time
   - Chef Automate shows compliance history

---

## 🚀 Scaling Implications

### Current Setup (Single Region)
- 5 nodes: ~10 minutes
- 50 nodes: ~15 minutes
- 500 nodes: ~30 minutes
- 1000+ nodes: ~40-50 minutes (chef-client convergence bottleneck)

### If You Need Faster Scaling
Option 1: **Wave-based deployment**
```
Run 1: 200 nodes (10 min)
Sleep: 5 min
Run 2: 200 nodes (10 min)
...
Total: 50 minutes for 1000 nodes
```

Option 2: **Multi-region deployment**
```
Region A: 500 nodes (30 min, parallel)
Region B: 500 nodes (30 min, parallel)
Total: 30 minutes for 1000 nodes globally
```

Option 3: **Use auto-scaling groups**
```
ASG target: 1000 instances
ASG launch: 1000 instances (5 min)
All convergence in parallel: 20 min
Total: 25 minutes
```

---

## ✅ Pre-Production Checklist

Before deploying to production:

- [ ] Tested workflow with 5 nodes ✓
- [ ] Verified nodes appear on Chef Server
- [ ] Compliance data in Chef Automate
- [ ] Can destroy and re-create seamlessly
- [ ] Scaling tested: 50 → 100 nodes
- [ ] Terraform state backed up / in S3
- [ ] Data collector token rotated / secured
- [ ] IAM roles least-privilege configured
- [ ] Network security groups reviewed
- [ ] Disaster recovery plan documented

Once all ✓ → ready for production 1000-node deployment
