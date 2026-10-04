# policy/tests/gap02_dynamodb_cmk_encryption_test.rego

package capstone.gap02_test

import rego.v1
import data.capstone.gap02

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "expressions": {
                        "server_side_encryption": [
                            {
                                "enabled": {
                                    "constant_value": true
                                },
                                "kms_key_arn": {
                                    "references": [
                                        "aws_kms_key.acme.arn"
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "values": {
                        "server_side_encryption": [
                            {
                                "enabled": true
                            }
                        ]
                    }
                }
            ]
        }
    }
}

noncompliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "expressions": {
                        "server_side_encryption": [
                            {
                                "enabled": {
                                    "constant_value": true
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "values": {
                        "server_side_encryption": [
                            {
                                "enabled": true
                            }
                        ]
                    }
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap02.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap02.deny with input as noncompliant_input
    contains(msg, "GAP-02")
    contains(msg, "aws_dynamodb_table.intake")
}