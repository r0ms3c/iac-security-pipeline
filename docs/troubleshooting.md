# Troubleshooting

## Pipeline does not trigger on push

**Symptom:** Push to repository but no Jenkins build starts.

**Check:**
1. GitLab webhook URL is correct — copy it directly from Jenkins → job → Configure → Build Triggers
2. Webhook secret token matches — update both sides if in doubt
3. Test webhook manually: GitLab → Settings → Webhooks → Test → Push events → should return HTTP 200
4. Jenkins job has the GitLab trigger enabled — check Configure → Build Triggers

---

## `repository not found` error in checkout

**Symptom:**
```
fatal: repository 'http://gitlab.internal/group/repo.git/' not found
```

**Check:**
1. `GITLAB_REPO_PATH` parameter is correct — must match the GitLab URL exactly (case-sensitive)
2. The `checkout-token` credential has at least Reporter access to the repository
3. GitLab → repository → Members — confirm the service account is listed

---

## All IaC types show `false`

**Symptom:**
```
Terraform     : false
Ansible       : false
Dockerfile    : false
```

**Check:**
1. Repository files are committed — `git status` should be clean
2. Files are within the first 6 directory levels — detection uses `-maxdepth 6`
3. Ansible detection requires YAML files with `hosts:` key at any level
4. Kubernetes detection requires YAML files with `apiVersion:` key

---

## Checkov returns 0 violations and 0 passed

**Symptom:** `Checkov — FAILED: 0 PASSED: 0`

**Check:**
1. Confirm YAML files are valid: `python3 -c "import yaml; yaml.safe_load(open('file.yml'))"`
2. Check if Checkov produced any output files: `ls /tmp/results_*.json`
3. Run manually on the Jenkins server: `sudo -u jenkins checkov --directory /path/to/repo`

---

## ansible-lint parse error

**Symptom:** ansible-lint fails with a Python or parse error.

**Fix:**
```bash
sudo /opt/ansible-env/bin/pip install --upgrade ansible ansible-lint
```

---

## HTML reports not generated

**Symptom:** `infra-security-report.html` missing from Jenkins artifacts.

**Check:**
1. Python 3 is available on the Jenkins server: `python3 --version`
2. Helper scripts were copied to `/tmp` — look for `cp generate-infra-report.py` in the log
3. JSON result files exist in the workspace — check for `trivy-report.json`, `checkov-report.json`
4. Check Python errors in the Generate report stage output

---

## Webhook returns HTTP 401

**Cause:** Secret token mismatch between GitLab and Jenkins.

**Fix:**
1. Get the correct token from Jenkins → job → Configure → Build Triggers → Advanced → Secret token
2. Update GitLab → Settings → Webhooks → edit → Secret token field
3. Test again — should return HTTP 200

Or apply the shared token via Script Console:

```groovy
def job = Jenkins.instance.getItemByFullName("job-name")
def trigger = job.getTriggers()?.values()?.find {
    it.class.name.contains("GitLab")
}
if (trigger) {
    trigger.secretToken = "your-shared-webhook-token"
    job.save()
    println "Done"
}
```

---

## Webhook returns HTTP 404

**Cause:** The webhook URL does not match the Jenkins job name.

**Fix:** Copy the URL directly from Jenkins → job → Configure → Build Triggers. The URL is shown on that page — do not type it manually.

---

## Token not persisting after Jenkins restart

**Cause:** Known bug in GitLab plugin v1.9.x where the secret token is not written to the correct XML location.

**Fix:** Define the trigger in the Jenkinsfile instead of the UI:

```groovy
triggers {
    gitlab(
        triggerOnPush: true,
        triggerOnMergeRequest: true,
        secretToken: "your-shared-webhook-token"
    )
}
```

After adding this and running the pipeline once, Jenkins writes the trigger to the correct XML location and it persists correctly.
