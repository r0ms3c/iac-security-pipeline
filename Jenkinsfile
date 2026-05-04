// ============================================================================
// IaC Security Pipeline
// Maintained by the Security Team
//
// Supports: Terraform · Ansible · Dockerfiles · Kubernetes YAML · Docker Compose
// IaC type detection is automatic — no manual configuration per project.
//
// Required Jenkins job parameters:
//   REPO_NAME         — Repository name (no spaces, use hyphens)
//   GITLAB_PROJECT_ID — Numeric GitLab project ID
//   GITLAB_REPO_PATH  — Repository path e.g. group/repo-name
//
// Required Jenkins credentials:
//   checkout-token       — Username/password for infrastructure repo checkout
//   pipeline-group-token — Group Access Token for this pipeline repo
//   gitlab-api-token     — GitLab API token for posting commit comments
// ============================================================================

pipeline {
    agent any

    environment {
        GITLAB_HOST = 'http://gitlab.internal'
    }

    stages {

        // ── Stage 1: Validate ─────────────────────────────────────────────
        stage('Validate configuration') {
            steps {
                script {
                    if (!env.REPO_NAME) {
                        error "REPO_NAME is not set."
                    }
                    if (!env.GITLAB_PROJECT_ID) {
                        error "GITLAB_PROJECT_ID is not set."
                    }
                    if (!env.GITLAB_REPO_PATH) {
                        error "GITLAB_REPO_PATH is not set."
                    }
                    if (env.REPO_NAME.contains(' ')) {
                        error "REPO_NAME '${env.REPO_NAME}' contains spaces. Use hyphens instead."
                    }
                    echo "Running infrastructure security pipeline for: ${env.REPO_NAME}"
                    echo "GitLab project ID: ${env.GITLAB_PROJECT_ID}"
                    echo "Repository path: ${env.GITLAB_REPO_PATH}"
                }
            }
        }

        // ── Stage 2: Checkout ─────────────────────────────────────────────
        stage('Checkout infrastructure code') {
            steps {
                script {
                    // Save helper scripts before workspace is overwritten
                    sh 'cp generate-infra-report.py /tmp/generate-infra-report.py'
                    sh 'cp scripts/merge-checkov.py /tmp/merge-checkov.py'
                    sh 'cp scripts/merge-hadolint.py /tmp/merge-hadolint.py'

                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: '*/main']],
                        userRemoteConfigs: [[
                            url: "${env.GITLAB_HOST}/${env.GITLAB_REPO_PATH}.git",
                            credentialsId: 'checkout-token'
                        ]]
                    ])

                    env.REPO_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                    echo "Infrastructure commit: ${env.REPO_COMMIT}"
                }
            }
        }

        // ── Stage 3: Detect IaC types ─────────────────────────────────────
        stage('Detect IaC types') {
            steps {
                script {
                    // Terraform — any *.tf file
                    env.HAS_TERRAFORM = sh(
                        script: 'find . -name "*.tf" -not -path "./.git/*" -maxdepth 6 | head -1',
                        returnStdout: true
                    ).trim() ? 'true' : 'false'

                    // Ansible — YAML files containing hosts: key
                    env.HAS_ANSIBLE = sh(
                        script: 'find . -not -path "./.git/*" -name "*.yml" | xargs grep -l "hosts:" 2>/dev/null | head -1 || true',
                        returnStdout: true
                    ).trim() ? 'true' : 'false'

                    // Dockerfiles
                    env.HAS_DOCKERFILE = sh(
                        script: 'find . -name "Dockerfile*" -not -path "./.git/*" -maxdepth 6 | head -1',
                        returnStdout: true
                    ).trim() ? 'true' : 'false'

                    // Kubernetes YAML — files containing apiVersion:
                    env.HAS_KUBERNETES = sh(
                        script: 'find . -not -path "./.git/*" -name "*.yml" | xargs grep -l "apiVersion:" 2>/dev/null | head -1 || true',
                        returnStdout: true
                    ).trim() ? 'true' : 'false'

                    // Docker Compose
                    env.HAS_COMPOSE = sh(
                        script: 'find . -not -path "./.git/*" -name "docker-compose*.yml" | head -1',
                        returnStdout: true
                    ).trim() ? 'true' : 'false'

                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    echo "IaC type detection results:"
                    echo "  Terraform     : ${env.HAS_TERRAFORM}"
                    echo "  Ansible       : ${env.HAS_ANSIBLE}"
                    echo "  Dockerfile    : ${env.HAS_DOCKERFILE}"
                    echo "  Kubernetes    : ${env.HAS_KUBERNETES}"
                    echo "  Docker Compose: ${env.HAS_COMPOSE}"
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                }
            }
        }

        // ── Stage 4: Trivy scan ───────────────────────────────────────────
        stage('Trivy scan') {
            steps {
                script {
                    sh 'rm -f trivy-report.json || true'

                    sh '''
                        trivy fs \
                          --scanners vuln,misconfig,secret \
                          --format json \
                          --output /tmp/trivy-report.json \
                          --exit-code 0 \
                          --severity HIGH,CRITICAL \
                          . 2>/dev/null || true
                    '''

                    def trivyContent = sh(
                        script: 'cat /tmp/trivy-report.json',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'trivy-report.json', text: trivyContent
                    archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true

                    def trivyJson  = readJSON file: 'trivy-report.json'
                    def results    = trivyJson.Results ?: []
                    def critical   = 0
                    def high       = 0
                    def misconfigs = 0
                    def secrets    = 0

                    results.each { r ->
                        r.Vulnerabilities?.each { v ->
                            def sev = v.Severity?.toUpperCase() ?: ''
                            if (sev == 'CRITICAL') critical++
                            else if (sev == 'HIGH') high++
                        }
                        r.Misconfigurations?.each { m ->
                            def sev = m.Severity?.toUpperCase() ?: ''
                            if (sev == 'CRITICAL' || sev == 'HIGH') misconfigs++
                        }
                        r.Secrets?.each { secrets++ }
                    }

                    echo "Trivy — CRITICAL: ${critical} HIGH: ${high} MISCONFIGS: ${misconfigs} SECRETS: ${secrets}"

                    env.TRIVY_CRITICAL   = "${critical}"
                    env.TRIVY_HIGH       = "${high}"
                    env.TRIVY_MISCONFIGS = "${misconfigs}"
                    env.TRIVY_SECRETS    = "${secrets}"

                    if (critical > 0 || high > 0 || misconfigs > 0 || secrets > 0) {
                        postGitlabComment(buildTrivyComment(results))
                    }
                    if (critical > 0 || secrets > 0) {
                        env.PIPELINE_FAILED = 'true'
                        env.PIPELINE_FAIL_REASON = (env.PIPELINE_FAIL_REASON ?
                            env.PIPELINE_FAIL_REASON + ' | ' : '') +
                            "Trivy found ${critical} CRITICAL CVEs and ${secrets} secrets."
                    }
                }
            }
        }

        // ── Stage 5: Checkov IaC scan ─────────────────────────────────────
        stage('Checkov IaC scan') {
            steps {
                script {
                    sh 'rm -f checkov-report.json || true'
                    sh 'checkov --directory . --output json --output-file-path /tmp --soft-fail --compact 2>/dev/null || true'
                    sh 'python3 /tmp/merge-checkov.py'

                    def checkovContent = sh(
                        script: 'cat /tmp/checkov-report.json',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'checkov-report.json', text: checkovContent
                    archiveArtifacts artifacts: 'checkov-report.json', allowEmptyArchive: true

                    def failed  = 0
                    def passed  = 0
                    def skipped = 0

                    try {
                        def checkovData = readJSON file: 'checkov-report.json'
                        def dataList = checkovData instanceof List ? checkovData : [checkovData]
                        dataList.each { section ->
                            def summary = section.summary ?: [:]
                            failed  += (summary.failed  ?: 0) as int
                            passed  += (summary.passed  ?: 0) as int
                            skipped += (summary.skipped ?: 0) as int
                        }
                    } catch (Exception e) {
                        echo "Warning: could not parse Checkov results: ${e.message}"
                    }

                    echo "Checkov — FAILED: ${failed} PASSED: ${passed} SKIPPED: ${skipped}"

                    env.CHECKOV_FAILED  = "${failed}"
                    env.CHECKOV_PASSED  = "${passed}"
                    env.CHECKOV_SKIPPED = "${skipped}"

                    if (failed > 0) {
                        postGitlabComment(buildCheckovComment())
                    }

                    // Adjust threshold to match your organisation's risk tolerance
                    if (failed > 10) {
                        env.PIPELINE_FAILED = 'true'
                        env.PIPELINE_FAIL_REASON = (env.PIPELINE_FAIL_REASON ?
                            env.PIPELINE_FAIL_REASON + ' | ' : '') +
                            "Checkov found ${failed} policy violations."
                    }
                }
            }
        }

        // ── Stage 6: ansible-lint ─────────────────────────────────────────
        stage('Ansible lint') {
            when {
                expression { env.HAS_ANSIBLE == 'true' }
            }
            steps {
                script {
                    sh 'rm -f ansible-lint-report.json || true'
                    sh 'ansible-lint --format json --nocolor . > /tmp/ansible-lint-report.json 2>/dev/null || true'

                    def ansibleContent = sh(
                        script: 'cat /tmp/ansible-lint-report.json 2>/dev/null || echo "[]"',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'ansible-lint-report.json', text: ansibleContent
                    archiveArtifacts artifacts: 'ansible-lint-report.json', allowEmptyArchive: true

                    def violations = 0
                    def errors     = 0
                    try {
                        def lintData = readJSON file: 'ansible-lint-report.json'
                        def findings = lintData instanceof List ? lintData : []
                        violations   = findings.size()
                        errors       = findings.count { it.severity == 'error' || it.level == 'error' }
                    } catch (Exception e) {
                        echo "Warning: could not parse ansible-lint results: ${e.message}"
                    }

                    echo "ansible-lint — VIOLATIONS: ${violations} ERRORS: ${errors}"

                    env.ANSIBLE_VIOLATIONS = "${violations}"
                    env.ANSIBLE_ERRORS     = "${errors}"

                    if (violations > 0) {
                        postGitlabComment(buildAnsibleComment())
                    }
                    if (errors > 0) {
                        env.PIPELINE_FAILED = 'true'
                        env.PIPELINE_FAIL_REASON = (env.PIPELINE_FAIL_REASON ?
                            env.PIPELINE_FAIL_REASON + ' | ' : '') +
                            "ansible-lint found ${errors} error-level violations."
                    }
                }
            }
        }

        // ── Stage 7: tflint ───────────────────────────────────────────────
        stage('Terraform lint') {
            when {
                expression { env.HAS_TERRAFORM == 'true' }
            }
            steps {
                script {
                    sh 'rm -f tflint-report.json || true'
                    sh 'tflint --init 2>/dev/null || true'
                    sh 'tflint --format json --recursive . > /tmp/tflint-report.json 2>/dev/null || true'

                    def tflintContent = sh(
                        script: 'cat /tmp/tflint-report.json 2>/dev/null || echo "{}"',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'tflint-report.json', text: tflintContent
                    archiveArtifacts artifacts: 'tflint-report.json', allowEmptyArchive: true

                    def issues = 0
                    def errors = 0
                    try {
                        def tflintData = readJSON file: 'tflint-report.json'
                        def issueList  = tflintData.issues ?: []
                        issues = issueList.size()
                        errors = issueList.count { it.rule?.severity == 'error' }
                    } catch (Exception e) {
                        echo "Warning: could not parse tflint results: ${e.message}"
                    }

                    echo "tflint — ISSUES: ${issues} ERRORS: ${errors}"

                    env.TFLINT_ISSUES = "${issues}"
                    env.TFLINT_ERRORS = "${errors}"

                    if (issues > 0) {
                        postGitlabComment(buildTflintComment())
                    }
                }
            }
        }

        // ── Stage 8: Hadolint ─────────────────────────────────────────────
        stage('Dockerfile lint') {
            when {
                expression { env.HAS_DOCKERFILE == 'true' }
            }
            steps {
                script {
                    sh 'rm -f hadolint-report.json || true'
                    sh 'find . -name "Dockerfile*" -not -path "./.git/*" | while read -r df; do hadolint --format json "$df" >> /tmp/hadolint-raw.json 2>/dev/null || true; done'
                    sh 'python3 /tmp/merge-hadolint.py'

                    def hadolintContent = sh(
                        script: 'cat /tmp/hadolint-report.json',
                        returnStdout: true
                    ).trim()
                    writeFile file: 'hadolint-report.json', text: hadolintContent
                    archiveArtifacts artifacts: 'hadolint-report.json', allowEmptyArchive: true

                    def errors   = 0
                    def warnings = 0
                    try {
                        def findings = readJSON file: 'hadolint-report.json'
                        def flist    = findings instanceof List ? findings : []
                        errors   = flist.count { it.level == 'error' }
                        warnings = flist.count { it.level == 'warning' || it.level == 'info' }
                    } catch (Exception e) {
                        echo "Warning: could not parse Hadolint results: ${e.message}"
                    }

                    echo "Hadolint — ERRORS: ${errors} WARNINGS: ${warnings}"

                    env.HADOLINT_ERRORS   = "${errors}"
                    env.HADOLINT_WARNINGS = "${warnings}"

                    if (errors > 0 || warnings > 0) {
                        postGitlabComment(buildHadolintComment())
                    }
                    if (errors > 0) {
                        env.PIPELINE_FAILED = 'true'
                        env.PIPELINE_FAIL_REASON = (env.PIPELINE_FAIL_REASON ?
                            env.PIPELINE_FAIL_REASON + ' | ' : '') +
                            "Hadolint found ${errors} Dockerfile errors."
                    }
                }
            }
        }

        // ── Stage 9: Generate infra security report ───────────────────────
        stage('Generate infra security report') {
            steps {
                script {
                    writeFile file: '/tmp/infra-report-env.sh', text: """
export REPO_NAME="${env.REPO_NAME}"
export GITLAB_REPO_PATH="${env.GITLAB_REPO_PATH}"
export REPO_COMMIT="${env.REPO_COMMIT}"
export GIT_BRANCH="${env.GIT_BRANCH ?: 'main'}"
export BUILD_NUMBER="${env.BUILD_NUMBER}"
export BUILD_URL="${env.BUILD_URL}"
export PIPELINE_STATUS="${env.PIPELINE_FAILED == 'true' ? 'FAILED' : 'PASSED'}"
export WORKSPACE="${env.WORKSPACE}"
export TRIVY_CRITICAL="${env.TRIVY_CRITICAL ?: '0'}"
export TRIVY_HIGH="${env.TRIVY_HIGH ?: '0'}"
export TRIVY_MISCONFIGS="${env.TRIVY_MISCONFIGS ?: '0'}"
export TRIVY_SECRETS="${env.TRIVY_SECRETS ?: '0'}"
export CHECKOV_FAILED="${env.CHECKOV_FAILED ?: '0'}"
export CHECKOV_PASSED="${env.CHECKOV_PASSED ?: '0'}"
export ANSIBLE_VIOLATIONS="${env.ANSIBLE_VIOLATIONS ?: '0'}"
export ANSIBLE_ERRORS="${env.ANSIBLE_ERRORS ?: '0'}"
export TFLINT_ISSUES="${env.TFLINT_ISSUES ?: '0'}"
export HADOLINT_ERRORS="${env.HADOLINT_ERRORS ?: '0'}"
export HADOLINT_WARNINGS="${env.HADOLINT_WARNINGS ?: '0'}"
export HAS_TERRAFORM="${env.HAS_TERRAFORM ?: 'false'}"
export HAS_ANSIBLE="${env.HAS_ANSIBLE ?: 'false'}"
export HAS_DOCKERFILE="${env.HAS_DOCKERFILE ?: 'false'}"
export HAS_KUBERNETES="${env.HAS_KUBERNETES ?: 'false'}"
export HAS_COMPOSE="${env.HAS_COMPOSE ?: 'false'}"
"""
                    writeFile file: '/tmp/infra-report-reason.txt',
                              text: env.PIPELINE_FAIL_REASON ?: ''

                    sh '''
                        . /tmp/infra-report-env.sh
                        export PIPELINE_FAIL_REASON=$(cat /tmp/infra-report-reason.txt)
                        python3 /tmp/generate-infra-report.py
                        rm -f /tmp/infra-report-env.sh /tmp/infra-report-reason.txt
                    '''

                    archiveArtifacts artifacts: 'infra-security-report.html,trivy-detail.html,checkov-detail.html', allowEmptyArchive: true
                    echo "Infrastructure security reports archived"
                }
            }
        }

        // ── Stage 10: Security Gate ───────────────────────────────────────
        stage('Security Gate') {
            steps {
                script {
                    if (env.PIPELINE_FAILED == 'true') {
                        error "Infrastructure pipeline failed: ${env.PIPELINE_FAIL_REASON}"
                    }
                }
            }
        }
    }

    post {
        success {
            script {
                def msg = "### Infrastructure Security Pipeline\n\n" +
                          "**Status: PASSED** ✅\n\n" +
                          "**Trivy:** CRITICAL: ${env.TRIVY_CRITICAL ?: 0} " +
                          "HIGH: ${env.TRIVY_HIGH ?: 0} " +
                          "MISCONFIGS: ${env.TRIVY_MISCONFIGS ?: 0}\n\n" +
                          "**Checkov:** ${env.CHECKOV_FAILED ?: 0} violations\n\n" +
                          "**ansible-lint:** ${env.ANSIBLE_VIOLATIONS ?: 0} violations\n\n" +
                          "**Hadolint:** ${env.HADOLINT_ERRORS ?: 0} errors"
                postGitlabComment(msg)
            }
            updateGitlabCommitStatus name: 'ci/jenkins-infra', state: 'success'
        }
        failure {
            updateGitlabCommitStatus name: 'ci/jenkins-infra', state: 'failed'
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

def buildTrivyComment(List results) {
    def critical = (env.TRIVY_CRITICAL ?: '0').toInteger()
    def high     = (env.TRIVY_HIGH     ?: '0').toInteger()
    def misconf  = (env.TRIVY_MISCONFIGS ?: '0').toInteger()
    def secrets  = (env.TRIVY_SECRETS   ?: '0').toInteger()
    def status   = (critical > 0 || secrets > 0) ? 'FAILED' : 'WARNING'
    def message  = "### Trivy Security Scan\n\n**Status: ${status}**\n\n"

    if (secrets > 0) {
        message += "#### 🔑 Secrets detected — ${secrets}\n\n"
        message += "_Secrets found in repository files — remove immediately and rotate._\n\n"
    }
    if (critical > 0) {
        message += "#### CVEs — CRITICAL: ${critical} HIGH: ${high}\n\n"
        results.take(3).each { r ->
            r.Vulnerabilities?.findAll { it.Severity == 'CRITICAL' }?.take(3)?.each { v ->
                message += "- **${v.VulnerabilityID}** | ${r.Target} | ${(v.Title ?: '').take(80)}\n"
            }
        }
        message += "\n"
    }
    if (misconf > 0) {
        message += "#### Misconfigurations — ${misconf} HIGH/CRITICAL\n\n"
        results.take(3).each { r ->
            r.Misconfigurations?.findAll {
                it.Severity == 'CRITICAL' || it.Severity == 'HIGH'
            }?.take(3)?.each { m ->
                message += "- **${m.ID}** | ${r.Target} | ${(m.Title ?: '').take(80)}\n"
            }
        }
        message += "\n"
    }
    message += "---\n_See trivy-detail.html in Jenkins artifacts for full report._"
    return message
}

def buildCheckovComment() {
    def failed = (env.CHECKOV_FAILED ?: '0').toInteger()
    def passed = (env.CHECKOV_PASSED ?: '0').toInteger()
    def message = "### Checkov IaC Policy Scan\n\n"
    message += "**Status: ${failed > 10 ? 'FAILED' : 'WARNING'}**\n\n"
    message += "- Failed checks: **${failed}**\n"
    message += "- Passed checks: **${passed}**\n\n"
    message += "---\n_See checkov-detail.html in Jenkins artifacts for full report._"
    return message
}

def buildAnsibleComment() {
    def violations = (env.ANSIBLE_VIOLATIONS ?: '0').toInteger()
    def errors     = (env.ANSIBLE_ERRORS ?: '0').toInteger()
    def status     = errors > 0 ? 'FAILED' : 'WARNING'
    def message    = "### ansible-lint\n\n**Status: ${status}**\n\n"
    message += "- Error-level violations: **${errors}**\n"
    message += "- Total violations: **${violations}**\n\n"
    message += "---\n_See infra-security-report.html in Jenkins artifacts for full report._"
    return message
}

def buildTflintComment() {
    def issues = (env.TFLINT_ISSUES ?: '0').toInteger()
    def errors = (env.TFLINT_ERRORS ?: '0').toInteger()
    def message = "### tflint Terraform Lint\n\n**Status: WARNING**\n\n"
    message += "- Issues found: **${issues}**\n"
    message += "- Errors: **${errors}**\n\n"
    message += "---\n_See infra-security-report.html in Jenkins artifacts for full report._"
    return message
}

def buildHadolintComment() {
    def errors   = (env.HADOLINT_ERRORS ?: '0').toInteger()
    def warnings = (env.HADOLINT_WARNINGS ?: '0').toInteger()
    def status   = errors > 0 ? 'FAILED' : 'WARNING'
    def message  = "### Hadolint Dockerfile Lint\n\n**Status: ${status}**\n\n"
    message += "- Errors: **${errors}**\n"
    message += "- Warnings: **${warnings}**\n\n"
    message += "---\n_See infra-security-report.html in Jenkins artifacts for full report._"
    return message
}

def postGitlabComment(String message) {
    def gitlabHost = env.GITLAB_HOST
    def projectId  = env.GITLAB_PROJECT_ID
    def commitSha  = env.REPO_COMMIT ?: env.GIT_COMMIT

    if (!projectId || !commitSha) {
        echo "Skipping GitLab comment — project ID or commit SHA not available"
        return
    }

    withCredentials([string(credentialsId: 'gitlab-api-token', variable: 'GL_TOKEN')]) {
        writeFile file: 'infra-comment-body.txt', text: message
        sh """
            python3 -c "
import json
with open('infra-comment-body.txt', 'r') as f:
    note = f.read()
payload = json.dumps({'note': note})
with open('infra-gitlab-comment.json', 'w') as f:
    f.write(payload)
"
            curl -s --request POST \\
              --header "PRIVATE-TOKEN: \$GL_TOKEN" \\
              --header "Content-Type: application/json" \\
              --data @infra-gitlab-comment.json \\
              "${gitlabHost}/api/v4/projects/${projectId}/repository/commits/${commitSha}/comments"
            rm -f infra-gitlab-comment.json infra-comment-body.txt
        """
    }
}
