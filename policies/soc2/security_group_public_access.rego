# SOC2 Control: CC6.6 (Network Security)
# LGPD: Art. 46 (Administrative and technical safeguards)
# ISO 27001: A.13.1.1 (Network controls)
#
# Requirement: Security Groups MUST follow principle of least privilege
# Rationale: Prevents unauthorized network access and reduces attack surface
# Severity: CRITICAL (public admin ports) / HIGH (public database ports)
# Auto-Remediation: Partially supported (requires approval for production)

package soc2.security_group_public_access

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Critical administrative ports that should NEVER be public
critical_admin_ports := [
    22,    # SSH
    3389,  # RDP (Windows Remote Desktop)
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
]

# Database ports that should NEVER be public
database_ports := [
    3306,  # MySQL/MariaDB
    5432,  # PostgreSQL
    1433,  # MSSQL
    1521,  # Oracle
    27017, # MongoDB
    27018, # MongoDB shard
    27019, # MongoDB config
    6379,  # Redis
    11211, # Memcached
    9042,  # Cassandra
    7000,  # Cassandra inter-node
    7001,  # Cassandra TLS inter-node
    9200,  # Elasticsearch
    9300,  # Elasticsearch inter-node
    5601,  # Kibana
]

# All critical ports combined
all_critical_ports := array.concat(critical_admin_ports, database_ports)

# CRITICAL: Administrative ports open to internet
deny[msg] {
    sg := input.resource.aws_security_group[name]
    ingress := sg.ingress[_]
    is_public_cidr(ingress)
    port := get_exposed_port(ingress, critical_admin_ports)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.6]: Security group '%s' exposes administrative port %d to internet", [name, port]),
        "details": sprintf("Port %d (%s) is publicly accessible from 0.0.0.0/0. This is an extreme security risk allowing unauthorized access attempts.", [port, port_description(port)]),
        "remediation": concat("\n", [
            sprintf("Restrict access to port %d:", [port]),
            sprintf("  resource \"aws_security_group\" \"%s\" {", [name]),
            "    ingress {",
            sprintf("      from_port   = %d", [port]),
            sprintf("      to_port     = %d", [port]),
            "      protocol    = \"tcp\"",
            "      cidr_blocks = [\"10.0.0.0/8\"]  # Replace with your VPN/bastion IP",
            "      description = \"Restricted admin access\"",
            "    }",
            "  }",
            "",
            "Better: Use Systems Manager Session Manager or bastion host in private subnet.",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.6", "LGPD-Art.46", "ISO27001-A.13.1.1"],
    }
}

# CRITICAL: Database ports open to internet
deny[msg] {
    sg := input.resource.aws_security_group[name]
    ingress := sg.ingress[_]
    is_public_cidr(ingress)
    port := get_exposed_port(ingress, database_ports)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.6]: Security group '%s' exposes database port %d to internet", [name, port]),
        "details": sprintf("Port %d (%s) is publicly accessible. Databases should NEVER be directly exposed to the internet.", [port, port_description(port)]),
        "remediation": concat("\n", [
            sprintf("Remove public access to port %d:", [port]),
            sprintf("  resource \"aws_security_group\" \"%s\" {", [name]),
            "    ingress {",
            sprintf("      from_port       = %d", [port]),
            sprintf("      to_port         = %d", [port]),
            "      protocol        = \"tcp\"",
            "      security_groups = [aws_security_group.app_tier.id]  # Allow only from app tier",
            "      description     = \"Database access from app tier only\"",
            "    }",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.6", "LGPD-Art.46"],
    }
}

# CRITICAL: All ports open to internet (0.0.0.0/0:0-65535)
deny[msg] {
    sg := input.resource.aws_security_group[name]
    ingress := sg.ingress[_]
    is_public_cidr(ingress)
    ingress.from_port == 0
    ingress.to_port == 65535

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.6]: Security group '%s' allows ALL ports from anywhere", [name]),
        "details": "This security group allows unrestricted access to ALL TCP/UDP ports (0-65535) from the internet. This is the most permissive configuration possible and violates all security best practices.",
        "remediation": concat("\n", [
            "IMMEDIATE ACTION REQUIRED:",
            "1. Identify which specific ports your application needs",
            "2. Replace the 0-65535 rule with specific port rules",
            "3. Restrict source IPs to minimum necessary (use security groups, not 0.0.0.0/0)",
            "",
            "Example for web application:",
            "  ingress {",
            "    from_port   = 443",
            "    to_port     = 443",
            "    protocol    = \"tcp\"",
            "    cidr_blocks = [\"0.0.0.0/0\"]  # OK for HTTPS",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.6"],
    }
}

# HIGH: Overly permissive port ranges
deny[msg] {
    sg := input.resource.aws_security_group[name]
    ingress := sg.ingress[_]
    is_public_cidr(ingress)

    # Port range > 100 ports is suspicious
    port_range := ingress.to_port - ingress.from_port
    port_range > 100

    msg := {
        "msg": sprintf("HIGH [SOC2-CC6.6]: Security group '%s' has overly broad port range (%d-%d)", [name, ingress.from_port, ingress.to_port]),
        "details": sprintf("Port range spans %d ports. Broad ranges increase attack surface unnecessarily.", [port_range + 1]),
        "remediation": "Define specific ports needed instead of broad ranges. Review application requirements.",
        "severity": "HIGH",
    }
}

# MEDIUM: Security group rules without descriptions
warn[msg] {
    sg := input.resource.aws_security_group[name]
    ingress := sg.ingress[_]
    not ingress.description

    msg := {
        "msg": sprintf("MEDIUM [Best Practice]: Security group '%s' has ingress rule without description", [name]),
        "details": "All security group rules should have descriptions explaining their purpose for audit and maintenance.",
        "remediation": sprintf("Add description to ingress rules in security group '%s'", [name]),
        "severity": "MEDIUM",
    }
}

# MEDIUM: Default security group should not have any rules
warn[msg] {
    sg := input.resource.aws_security_group[name]
    sg.name == "default"
    count(sg.ingress) > 0

    msg := {
        "msg": sprintf("MEDIUM [Best Practice]: Default security group '%s' has custom rules", [name]),
        "details": "AWS best practice is to leave default security groups empty and create custom security groups instead.",
        "remediation": "Create custom security groups and avoid modifying the default.",
        "severity": "MEDIUM",
    }
}

# LOW: IPv6 public access without IPv4
warn[msg] {
    sg := input.resource.aws_security_group[name]
    ingress := sg.ingress[_]

    cidr := ingress.ipv6_cidr_blocks[_]
    cidr == "::/0"

    # No corresponding IPv4 rule
    not ingress.cidr_blocks

    msg := {
        "msg": sprintf("LOW [Best Practice]: Security group '%s' allows IPv6 public access but not IPv4", [name]),
        "details": "Inconsistent IPv4/IPv6 rules can lead to security gaps. Ensure both protocols have consistent policies.",
        "remediation": "Review IPv4 and IPv6 rules for consistency.",
        "severity": "LOW",
    }
}

# Helper: Check if ingress allows public CIDR
is_public_cidr(ingress) if {
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"
}

is_public_cidr(ingress) if {
    cidr := ingress.ipv6_cidr_blocks[_]
    cidr == "::/0"
}

# Helper: Get exposed port from specific port list
get_exposed_port(ingress, port_list) := port if {
    port := port_list[_]
    port_is_exposed(ingress, port)
}

# Helper: Check if specific port is exposed
port_is_exposed(ingress, port) if {
    ingress.from_port == port
    ingress.to_port == port
}

port_is_exposed(ingress, port) if {
    port >= ingress.from_port
    port <= ingress.to_port
}

# Helper: Get human-readable port description
port_description(port) := "SSH" if { port == 22 }
port_description(port) := "RDP" if { port == 3389 }
port_description(port) := "MySQL" if { port == 3306 }
port_description(port) := "PostgreSQL" if { port == 5432 }
port_description(port) := "MSSQL" if { port == 1433 }
port_description(port) := "MongoDB" if { port == 27017 }
port_description(port) := "Redis" if { port == 6379 }
port_description(port) := "Elasticsearch" if { port == 9200 }
port_description(port) := sprintf("Port %d", [port]) if {
    not port in [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200]
}
