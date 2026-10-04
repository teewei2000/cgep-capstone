# policy/tests/gap03_s3_tls_test.rego

package capstone.gap03_test

import rego.v1
import data.capstone.gap03

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket"
                },
                {
                    "address": "aws_s3_bucket_policy.uploads_tls",
                    "type": "aws_s3_bucket_policy",
                    "expressions": {
                        "bucket": {
                            "references": [
                                "aws_s3_bucket.uploads.id"
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
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket"
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap03.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap03.deny with input as noncompliant_input
    contains(msg, "GAP-03")
    contains(msg, "aws_s3_bucket.uploads")
}