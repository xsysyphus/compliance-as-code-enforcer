# SOC2 Control: A1.2 (Availability - Data Backup and Recovery)
# LGPD: Art. 46 (Security and business continuity)
# ISO 27001: A.12.3.1 (Information backup)
#
# Requirement: RDS instances MUST have proper backup configuration for disaster recovery
# Rationale: Ensures business continuity and data recovery capability in case of failures
# Severity: HIGH (backup) / CRITICAL (encryption, public access)
# Auto-Remediation: Supported

package soc2.rds_backup_retention

import future.keywords.if
import future.keywords.in

# Configuration constants
min_retention_days := 7
recommended_retention_days := 30
max_skip_final_snapshot_environments := ["development", "dev", "test", "sandbox"]

# CRITICAL: RDS instances MUST NOT be publicly accessible
deny[msg] {
    db := input.resource.aws_db_instance[name]
    db.publicly_accessible == true

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.6]: RDS instance '%s' is publicly accessible", [name]),
        "details": "Database instances should never be directly accessible from the internet. This violates the principle of defense in depth.",
        "remediation": concat("\n", [
            "Set publicly_accessible = false:",
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            "    publicly_accessible = false",
            "    # Place in private subnet",
            "    db_subnet_group_name = aws_db_subnet_group.private.name",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.6", "LGPD-Art.46"],
    }
}

# CRITICAL: RDS instances MUST have encryption at rest enabled
deny[msg] {
    db := input.resource.aws_db_instance[name]
    not db.storage_encrypted

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.7]: RDS instance '%s' does not have encryption at rest enabled", [name]),
        "details": "All database instances must encrypt data at rest to protect confidentiality of stored data.",
        "remediation": concat("\n", [
            "Enable storage encryption:",
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            "    storage_encrypted = true",
            "    kms_key_id       = aws_kms_key.rds.arn  # Optional: use customer-managed key",
            "  }",
            "",
            "Note: Encryption cannot be enabled on existing unencrypted instances.",
            "You must create a snapshot, copy it with encryption, and restore from the encrypted snapshot.",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.7", "LGPD-Art.46", "ISO27001-A.10.1.1"],
    }
}

# HIGH: RDS instances with insufficient backup retention
deny[msg] {
    db := input.resource.aws_db_instance[name]
    retention := get_retention_period(db)
    retention > 0
    retention < min_retention_days

    msg := {
        "msg": sprintf("HIGH [SOC2-A1.2]: RDS instance '%s' has insufficient backup retention (%d days)", [name, retention]),
        "details": sprintf("Backup retention is set to %d days but SOC2 requires at least %d days for disaster recovery capability.", [retention, min_retention_days]),
        "remediation": concat("\n", [
            sprintf("Increase backup retention to at least %d days:", [min_retention_days]),
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            sprintf("    backup_retention_period = %d  # Or higher (recommended: %d)", [min_retention_days, recommended_retention_days]),
            "    backup_window           = \"03:00-04:00\"  # UTC",
            "    maintenance_window      = \"mon:04:00-mon:05:00\"",
            "  }",
        ]),
        "severity": "HIGH",
        "compliance": ["SOC2-A1.2", "ISO27001-A.12.3.1"],
    }
}

# CRITICAL: RDS instances with backups completely disabled
deny[msg] {
    db := input.resource.aws_db_instance[name]
    not db.backup_retention_period

    # Allow skip only for non-production environments
    not is_non_production_environment(db)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-A1.2]: RDS instance '%s' has automated backups disabled", [name]),
        "details": "Production databases must have automated backups enabled to ensure recoverability.",
        "remediation": concat("\n", [
            sprintf("Enable automated backups with at least %d days retention:", [min_retention_days]),
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            sprintf("    backup_retention_period = %d", [min_retention_days]),
            "    backup_window           = \"03:00-04:00\"",
            "    copy_tags_to_snapshot   = true",
            "    delete_automated_backups = false",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-A1.2"],
    }
}

# HIGH: Production RDS should not skip final snapshot
deny[msg] {
    db := input.resource.aws_db_instance[name]
    db.skip_final_snapshot == true
    not is_non_production_environment(db)

    msg := {
        "msg": sprintf("HIGH [SOC2-A1.2]: Production RDS instance '%s' will skip final snapshot on deletion", [name]),
        "details": "Production databases should create a final snapshot before deletion to prevent accidental data loss.",
        "remediation": concat("\n", [
            "Configure final snapshot settings:",
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            "    skip_final_snapshot       = false",
            sprintf("    final_snapshot_identifier = \"%s-final-snapshot\"", [name]),
            "  }",
        ]),
        "severity": "HIGH",
        "compliance": ["SOC2-A1.2"],
    }
}

# MEDIUM: RDS instances should have deletion protection enabled
warn[msg] {
    db := input.resource.aws_db_instance[name]
    not db.deletion_protection
    not is_non_production_environment(db)

    msg := {
        "msg": sprintf("MEDIUM [SOC2-A1.2]: RDS instance '%s' lacks deletion protection", [name]),
        "details": "Production databases should have deletion protection to prevent accidental deletion.",
        "remediation": sprintf("Set deletion_protection = true for instance '%s'", [name]),
        "severity": "MEDIUM",
    }
}

# MEDIUM: RDS should have enhanced monitoring enabled
warn[msg] {
    db := input.resource.aws_db_instance[name]
    not db.enabled_cloudwatch_logs_exports
    not is_non_production_environment(db)

    msg := {
        "msg": sprintf("MEDIUM [SOC2-CC7.2]: RDS instance '%s' does not export logs to CloudWatch", [name]),
        "details": "Enable CloudWatch Logs export for audit trails and performance monitoring.",
        "remediation": concat("\n", [
            "Enable log exports (engine-specific):",
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            "    enabled_cloudwatch_logs_exports = [\"error\", \"general\", \"slowquery\"]  # For MySQL",
            "    # For PostgreSQL: [\"postgresql\", \"upgrade\"]",
            "  }",
        ]),
        "severity": "MEDIUM",
    }
}

# LOW: Backup window should be explicitly configured
warn[msg] {
    db := input.resource.aws_db_instance[name]
    not db.backup_window
    get_retention_period(db) > 0

    msg := {
        "msg": sprintf("LOW [Best Practice]: RDS instance '%s' should specify backup_window", [name]),
        "details": "Explicitly define backup window to ensure backups occur during low-traffic periods.",
        "remediation": sprintf("Add backup_window = \"03:00-04:00\" to instance '%s' (adjust for your timezone)", [name]),
        "severity": "LOW",
    }
}

# LOW: Maintenance window should be explicitly configured
warn[msg] {
    db := input.resource.aws_db_instance[name]
    not db.maintenance_window

    msg := {
        "msg": sprintf("LOW [Best Practice]: RDS instance '%s' should specify maintenance_window", [name]),
        "details": "Explicitly define maintenance window to control when updates occur.",
        "remediation": sprintf("Add maintenance_window = \"mon:04:00-mon:05:00\" to instance '%s'", [name]),
        "severity": "LOW",
    }
}

# MEDIUM: Multi-AZ should be enabled for production databases
warn[msg] {
    db := input.resource.aws_db_instance[name]
    not db.multi_az
    not is_non_production_environment(db)
    not is_read_replica(db)

    msg := {
        "msg": sprintf("MEDIUM [SOC2-A1.1]: RDS instance '%s' is not configured for Multi-AZ", [name]),
        "details": "Production databases should use Multi-AZ for high availability and automatic failover.",
        "remediation": sprintf("Set multi_az = true for instance '%s' (requires downtime)", [name]),
        "severity": "MEDIUM",
        "compliance": ["SOC2-A1.1"],
    }
}

# Helper: Get retention period, default to 0 if not specified
get_retention_period(db) := retention if {
    retention := db.backup_retention_period
} else := 0

# Helper: Check if database is in non-production environment
is_non_production_environment(db) if {
    env := lower(db.tags.Environment)
    env_name := max_skip_final_snapshot_environments[_]
    env == env_name
}

is_non_production_environment(db) if {
    identifier := lower(db.identifier)
    contains(identifier, "dev")
}

is_non_production_environment(db) if {
    identifier := lower(db.identifier)
    contains(identifier, "test")
}

# Helper: Check if instance is a read replica
is_read_replica(db) if {
    db.replicate_source_db
}
