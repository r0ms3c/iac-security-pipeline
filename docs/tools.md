# Tools

All tools run on the Jenkins server (Ubuntu 24.04 LTS). Install once — all pipeline jobs share the installations.

## Installation scripts

Individual scripts are in `scripts/install/`. Run the master script as root:

```bash
sudo bash scripts/install/install-all.sh
```

Or install individually:

```bash
sudo bash scripts/install/01-install-trivy.sh
sudo bash scripts/install/02-install-checkov.sh
sudo bash scripts/install/03-install-ansible-lint.sh
sudo bash scripts/install/04-install-tflint.sh
sudo bash scripts/install/05-install-hadolint.sh
```

---

## Trivy

**Version:** latest via Aqua Security apt repository  
**Binary:** `/usr/local/bin/trivy`  
**Documentation:** https://trivy.dev

```bash
# Install
apt-get install -y wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
https://aquasecurity.github.io/trivy-repo/deb generic main" \
    | tee /etc/apt/sources.list.d/trivy.list
apt-get update && apt-get install -y trivy

# Update vulnerability database
trivy image --download-db-only

# Update
apt-get install --only-upgrade trivy
```

**What it scans:** Dockerfiles, Kubernetes YAML, Terraform, filesystem  
**Detects:** OS and library CVEs · container misconfigurations · secrets in files

---

## Checkov

**Version:** latest via pip  
**Binary:** `/opt/checkov-env/bin/checkov` → symlink at `/usr/local/bin/checkov`  
**Documentation:** https://www.checkov.io

```bash
# Install
python3 -m venv /opt/checkov-env
/opt/checkov-env/bin/pip install --upgrade pip checkov
ln -sf /opt/checkov-env/bin/checkov /usr/local/bin/checkov

# Update
/opt/checkov-env/bin/pip install --upgrade checkov
```

**What it scans:** Terraform · Ansible · Kubernetes · Docker Compose · Dockerfiles · secrets  
**Detects:** Policy violations against CIS benchmarks and security best practices

---

## ansible-lint

**Version:** latest via pip  
**Binary:** `/opt/ansible-env/bin/ansible-lint` → symlink at `/usr/local/bin/ansible-lint`  
**Documentation:** https://ansible.readthedocs.io/projects/lint

```bash
# Install
python3 -m venv /opt/ansible-env
/opt/ansible-env/bin/pip install --upgrade pip ansible ansible-lint
ln -sf /opt/ansible-env/bin/ansible-lint /usr/local/bin/ansible-lint

# Update
/opt/ansible-env/bin/pip install --upgrade ansible ansible-lint
```

**What it scans:** Ansible playbooks and roles  
**Detects:** Deprecated syntax · privilege escalation issues · risky file permissions · bad practices

---

## tflint

**Version:** latest binary release from GitHub  
**Binary:** `/usr/local/bin/tflint`  
**Documentation:** https://github.com/terraform-linters/tflint

```bash
# Install
TFLINT_VERSION=$(curl -s https://api.github.com/repos/terraform-linters/tflint/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4)
curl -sLo /tmp/tflint.zip \
    "https://github.com/terraform-linters/tflint/releases/download/${TFLINT_VERSION}/tflint_linux_amd64.zip"
unzip -qo /tmp/tflint.zip -d /usr/local/bin/
chmod +x /usr/local/bin/tflint

# Update — re-run install script
```

**What it scans:** Terraform .tf files  
**Detects:** Syntax errors · naming violations · deprecated resources · missing fields

---

## Hadolint

**Version:** latest binary release from GitHub  
**Binary:** `/usr/local/bin/hadolint`  
**Documentation:** https://github.com/hadolint/hadolint

```bash
# Install
HADOLINT_VERSION=$(curl -s https://api.github.com/repos/hadolint/hadolint/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4)
curl -sLo /usr/local/bin/hadolint \
    "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64"
chmod +x /usr/local/bin/hadolint

# Update — re-run install script
```

**What it scans:** Dockerfiles  
**Detects:** Running as root · shell form CMD · missing HEALTHCHECK · apt without version pinning

---

## Verifying installations

```bash
trivy --version
checkov --version
ansible-lint --version
tflint --version
hadolint --version
```

All should return version numbers. If any command is not found, re-run the corresponding install script.
