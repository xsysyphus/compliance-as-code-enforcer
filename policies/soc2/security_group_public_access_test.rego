# Unit tests for security group public access policy
package soc2.security_group_public_access

# Test: Deny SSH exposed to the internet
test_deny_public_ssh {
    test_input := {
        "resource": {
            "aws_security_group": {
                "sg_public_ssh": {
                    "ingress": [{
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Deny database port exposed publicly
test_deny_public_database {
    test_input := {
        "resource": {
            "aws_security_group": {
                "sg_public_db": {
                    "ingress": [{
                        "from_port": 5432,
                        "to_port": 5432,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: High severity for overly broad port range
test_high_broad_port_range {
    test_input := {
        "resource": {
            "aws_security_group": {
                "sg_broad_range": {
                    "ingress": [{
                        "from_port": 1000,
                        "to_port": 1300,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    # Should trigger broad port range rule
    count(results) > 0
}

# Test: Warn when rule lacks description (non-public ingress)
test_warn_missing_description {
    test_input := {
        "resource": {
            "aws_security_group": {
                "sg_internal": {
                    "ingress": [{
                        "from_port": 8080,
                        "to_port": 8080,
                        "protocol": "tcp",
                        "cidr_blocks": ["10.0.0.0/8"]
                    }]
                }
            }
        }
    }

    results := warn with input as test_input
    count(results) > 0
}
