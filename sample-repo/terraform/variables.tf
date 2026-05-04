# ── Terraform variable definitions ────────────────────────────────────────────

variable "server_count" {
  description = "Number of application servers to provision"
  type        = number
  default     = 2

  validation {
    condition     = var.server_count >= 1 && var.server_count <= 10
    error_message = "Server count must be between 1 and 10."
  }
}

variable "enable_monitoring" {
  description = "Enable monitoring agent on servers"
  type        = bool
  default     = false  # SECURITY ISSUE: monitoring disabled by default
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 7  # SECURITY ISSUE: too short for compliance (PCI-DSS requires 12 months)
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
  default     = ""
}

variable "backup_enabled" {
  description = "Enable automated backups"
  type        = bool
  default     = false  # SECURITY ISSUE: backups disabled
}
