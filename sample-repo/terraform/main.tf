# ============================================================
# Sample Infrastructure — Terraform Configuration
# On-premises VMware / generic provider example
# Note: contains intentional security issues for pipeline testing
# ============================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }

  # Backend configuration — store state locally for this sample
  # In production use a remote backend (e.g. Terraform Cloud, GitLab)
  backend "local" {
    path = "terraform.tfstate"
  }
}

# ── Variables ──────────────────────────────────────────────────────────────────
variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "development"
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "sample-app"
}

variable "db_password" {
  description = "Database password"
  type        = string
  # SECURITY ISSUE: hardcoded default password — use secrets manager instead
  default     = "Password123!"
  sensitive   = true
}

variable "admin_cidr" {
  description = "CIDR range allowed for admin access"
  type        = string
  # SECURITY ISSUE: open to all — should be restricted to management network
  default     = "0.0.0.0/0"
}

# ── Local values ───────────────────────────────────────────────────────────────
locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Project     = var.app_name
    Owner       = "security-team"
  }
}

# ── Sample local file resource (represents server config) ──────────────────────
resource "local_file" "app_config" {
  filename = "${path.module}/output/app-config.json"
  content  = jsonencode({
    app_name    = var.app_name
    environment = var.environment
    # SECURITY ISSUE: writing password to config file
    db_password = var.db_password
    admin_cidr  = var.admin_cidr
  })

  # SECURITY ISSUE: file permissions too open
  file_permission = "0644"
}

resource "local_file" "network_config" {
  filename        = "${path.module}/output/network-config.json"
  file_permission = "0600"
  content         = jsonencode({
    # SECURITY ISSUE: HTTP not HTTPS
    api_endpoint  = "http://internal-api.sample.local:8080"
    admin_cidr    = var.admin_cidr
    tags          = local.common_tags
  })
}

# ── Null resource simulating server provisioning ───────────────────────────────
resource "null_resource" "server_setup" {
  triggers = {
    app_name = var.app_name
  }

  provisioner "local-exec" {
    command = "echo 'Server ${var.app_name} provisioned in ${var.environment}'"
  }
}
