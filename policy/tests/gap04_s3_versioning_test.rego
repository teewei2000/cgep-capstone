# policy/tests/gap04_s3_versioning_test.rego
package capstone.gap04_test

import rego.v1
import data.capstone.gap04

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket"
                },
                {
                    "address": "aws_s3_bucket_versioning.uploads",
                    "type": "aws_s3_bucket_versioning",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.uploads.id"
                            ]
                        },
                        "versioning_configuration": [
                            {
                                "status": {
                                    "constant_value": "Enabled"
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
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket"
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap04.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap04.deny with input as noncompliant_input
    contains(msg, "GAP-04")
    contains(msg, "aws_s3_bucket.uploads")
}