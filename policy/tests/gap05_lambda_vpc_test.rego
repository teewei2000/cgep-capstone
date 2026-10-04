# policy/tests/gap05_lambda_vpc_test.rego
package capstone.gap05_test

import rego.v1
import data.capstone.gap05

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_lambda_function.intake",
                    "type": "aws_lambda_function",
                    "expressions": {
                        "vpc_config": [
                            {
                                "subnet_ids": {
                                    "references": [
                                        "aws_subnet.private"
                                    ]
                                },
                                "security_group_ids": {
                                    "references": [
                                        "aws_security_group.lambda.id"
                                    ]
                                }
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
                    "address": "aws_lambda_function.intake",
                    "type": "aws_lambda_function",
                    "expressions": {}
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap05.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap05.deny with input as noncompliant_input
    contains(msg, "GAP-05")
    contains(msg, "aws_lambda_function.intake")
}