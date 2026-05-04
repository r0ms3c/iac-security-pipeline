# Sample Infrastructure Repository

This directory contains a complete set of infrastructure files with intentional security issues. Use it to verify that all pipeline tools are working correctly after installation.

## Structure

```
sample-repo/
├── terraform/
│   ├── main.tf          ← Terraform with insecure defaults
│   ├── variables.tf     ← Variables with weak settings
│   └── outputs.tf       ← Sensitive output not marked sensitive
├── ansible/
│   ├── playbooks/
│   │   └── site.yml     ← Playbook with hardcoded credentials
│   ├── roles/webserver/
│   └── inventory/
│       └── hosts.ini
├── docker/
│   ├── Dockerfile       ← Container running as root, secrets in ENV
│   └── docker-compose.yml ← Privileged container, docker socket mount
└── kubernetes/
    └── deployment.yml   ← No resource limits, running as root
```

## Expected findings

After running the pipeline against this repository, each tool should find issues:

### Trivy
- `DS-0002` — Container running as root (Dockerfile)
- `DS-0031` — Secrets in ENV variables (DB_PASSWORD, APP_SECRET)
- `KSV-0014` — Root filesystem not read-only (Kubernetes)
- `KSV-0017` — Privileged container (Kubernetes)

### Checkov
- `CKV_K8S_16` — Container should not be privileged
- `CKV_K8S_23` — Minimise root containers
- `CKV_K8S_11` — CPU limits not set
- `CKV_K8S_13` — Memory limits not set
- `CKV_DOCKER_2` — No HEALTHCHECK instruction
- `CKV_DOCKER_3` — No non-root USER defined
- `CKV_SECRET_6` — Base64 high entropy string (hardcoded passwords)

### ansible-lint
- Hardcoded credentials in playbook variables
- Directory permissions set to 0777
- Deprecated module syntax

### tflint
- Variable naming and constraint issues
- Informative findings only (does not block)

### Hadolint
- `DL3002` — Last USER is root
- `DL3025` — Use JSON notation for CMD
- `DL3029` — Do not use `--platform` flag

## Usage

To run the pipeline against this sample repository:

1. Create a GitLab repository and push these files
2. Follow the [onboarding guide](../docs/onboarding.md) to add it to the pipeline
3. Push a commit and verify the pipeline finds all expected issues

If any tool finds nothing, check the installation instructions in [docs/tools.md](../docs/tools.md).
