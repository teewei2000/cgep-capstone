# policy/gap01_s3_cmk_encryption.rego
# METADATA
# title: GAP-01 - S3 PHI bucket must use SSE-KMS with customer CMK
# description: "Every aws_s3_bucket holding PHI must use aws:kms encryption with a customer CMK, not AWS-managed SSE-S3."
# custom:
#   gap_id: GAP-01
#   hipaa: "164.312(a)(2)(iv)"
#   control_id: "164.312(a)(2)(iv)"
#   severity: critical

package capstone.gap01

import rego.v1

deny contains msg if {
    bucket := bucket_addresses[_]
    not has_kms_encryption(bucket)

    msg := sprintf(
        "[GAP-01][HIPAA 164.312(a)(2)(iv)] %s: PHI bucket lacks SSE-KMS with customer CMK. Remediation: add encryption config with sse_algorithm=aws:kms and a CMK.",
        [bucket],
    )
}

bucket_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket"
    addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms_encryption(bucket_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket_server_side_encryption_configuration"

    some ref in r.expressions.bucket.references
    references_bucket(ref, bucket_addr)

    kms_algorithm_present
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

kms_algorithm_present if {
    some pr in input.planned_values.root_module.resources
    pr.type == "aws_s3_bucket_server_side_encryption_configuration"

    some enc_rule in pr.values.rule
    some enc_default in enc_rule.apply_server_side_encryption_by_default

    enc_default.sse_algorithm == "aws:kms"
}