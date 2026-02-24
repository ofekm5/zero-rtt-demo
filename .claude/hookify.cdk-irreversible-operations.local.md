---
name: cdk-irreversible-operations
enabled: true
event: bash
pattern: cdk\s+(deploy|destroy)
action: warn
---

⚠️ **AWS CDK Irreversible Operation Detected**

You're about to run a CDK command that can make irreversible changes to AWS infrastructure:
- `cdk deploy` - Provisions/updates AWS resources
- `cdk destroy` - Deletes AWS resources and data

**Before proceeding, verify:**
- [ ] You're targeting the correct AWS account/region
- [ ] You've reviewed the changeset/diff
- [ ] You have proper permissions and authorization
- [ ] You understand the impact of these changes
- [ ] You have backups if destroying resources with data

**Tip:** Use `cdk diff` first to preview changes without applying them.