package capstone.gap07_test

import rego.v1
import data.capstone.gap07

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_iam_role_policy.lambda_inline",
                    "type": "aws_iam_role_policy",
                    "expressions": {
                        "role": {
                            "references": [
                                "aws_iam_role.lambda"
                            ]
                        },
                        "policy": {
                            "references": [
                                "aws_dynamodb_table.intake.arn",
                                "aws_s3_bucket.uploads.arn",
                                "aws_kms_key.acme.arn"
                            ]
                        }
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
                    "address": "aws_iam_role_policy.lambda_inline",
                    "type": "aws_iam_role_policy",
                    "expressions": {
                        "role": {
                            "references": [
                                "aws_iam_role.lambda"
                            ]
                        },
                        "policy": {
                            "references": [
                                "aws_dynamodb_table.intake.arn",
                                "aws_s3_bucket.uploads.arn"
                            ]
                        }
                    }
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap07.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap07.deny with input as noncompliant_input
    contains(msg, "GAP-07")
    contains(msg, "164.312(a)(1)")
}