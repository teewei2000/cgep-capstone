# policy/tests/gap01_s3_cmk_encryption_test.rego

package capstone.gap01_test

import rego.v1
import data.capstone.gap01

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket",
                    "name": "uploads"
                },
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                    "name": "uploads",
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
    },
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket",
                    "values": {}
                },
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                    "values": {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {
                                        "sse_algorithm": "aws:kms",
                                        "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/test-key"
                                    }
                                ],
                                "bucket_key_enabled": true
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
                    "type": "aws_s3_bucket",
                    "name": "uploads"
                }
            ]
        }
    },
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket.uploads",
                    "type": "aws_s3_bucket",
                    "values": {}
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap01.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap01.deny with input as noncompliant_input
    contains(msg, "GAP-01")
    contains(msg, "aws_s3_bucket.uploads")
}