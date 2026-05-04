# ── Terraform outputs ─────────────────────────────────────────────────────────

output "app_config_path" {
  description = "Path to generated application config"
  value       = local_file.app_config.filename
}

output "environment" {
  description = "Deployment environment"
  value       = var.environment
}

# SECURITY ISSUE: outputting sensitive value without sensitive = true
output "db_connection_string" {
  description = "Database connection string"
  value       = "postgresql://app:${var.db_password}@db.internal:5432/appdb"
  sensitive   = false
}
