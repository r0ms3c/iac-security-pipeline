# Onboarding a new infrastructure repository

Three steps · approximately 10 minutes

---

## Step 1 — Create the Jenkins job

**Jenkins → New Item**

| Field | Value |
|---|---|
| Item name | `repo-name` (no spaces — use hyphens) |
| Type | Pipeline |

**Configure → This project is parameterised → Add three String Parameters:**

| Name | Description | Example |
|---|---|---|
| `REPO_NAME` | Repository name, no spaces | `my-infrastructure` |
| `GITLAB_PROJECT_ID` | Numeric ID from GitLab → Settings → General | `42` |
| `GITLAB_REPO_PATH` | Path after the domain | `group/my-infrastructure` |

**Build Triggers → Build when a change is pushed to GitLab → Advanced → Secret token → Generate**

Copy the generated token — you will need it in Step 3.

**Pipeline section:**

| Field | Value |
|---|---|
| Definition | Pipeline script from SCM |
| SCM | Git |
| Repository URL | `<your-gitlab>/security-pipeline/infra-security-pipeline.git` |
| Credentials | `pipeline-group-token` |
| Branch specifier | `*/main` |
| Script path | `Jenkinsfile` |

Click **Save**.

Apply the webhook token via Jenkins Script Console to ensure it persists:

```groovy
def job = Jenkins.instance.getItemByFullName("repo-name")
def trigger = job.getTriggers()?.values()?.find {
    it.class.name.contains("GitLab")
}
if (trigger) {
    trigger.secretToken = "your-shared-webhook-token"
    job.save()
    println "Done: ${job.fullName}"
}
```

Run **Build with Parameters** once to activate the pipeline trigger.

---

## Step 2 — Add a stub Jenkinsfile to the infrastructure repository

Create a file named `Jenkinsfile` (no extension) in the repository root:

```
// Infrastructure security pipeline — managed centrally by the security team.
// Do not modify this file. Contact the security team for pipeline changes.
// Pipeline source: <your-gitlab>/security-pipeline/infra-security-pipeline
```

Commit and push:

```bash
git add Jenkinsfile
git commit -m "Add security pipeline stub Jenkinsfile"
git push
```

---

## Step 3 — Add the GitLab webhook

**GitLab → repository → Settings → Webhooks → Add new webhook**

| Field | Value |
|---|---|
| URL | Copy from Jenkins → job → Configure → Build Triggers |
| Secret token | Your shared webhook token |
| Push events | ✓ Enable |
| Merge request events | ✓ Enable |
| SSL verification | Disable if Jenkins has no TLS certificate |

Click **Add webhook** → **Test → Push events** → verify HTTP 200.

---

## Verification

After completing all three steps, push a test commit:

```bash
echo "# security pipeline test" >> README.md
git add README.md
git commit -m "Test infrastructure security pipeline"
git push
```

After 2-3 minutes check the GitLab commit — you should see comments from Jenkins with the scan results and a pass or fail status.

---

## IaC type detection

The pipeline automatically detects what to scan — no configuration needed:

| Detected when | Tool activated |
|---|---|
| Any `*.tf` file exists | tflint (Terraform lint) |
| Any YAML file contains `hosts:` | ansible-lint |
| Any `Dockerfile*` exists | Hadolint |
| Any YAML file contains `apiVersion:` | Checkov K8s rules |
| Any `docker-compose*.yml` exists | Checkov Compose rules |

Trivy and Checkov always run regardless of detected types.
