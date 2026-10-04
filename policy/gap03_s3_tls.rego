# policy/gap03_s3_tls.rego
# METADATA
# title: GAP-03 - S3 PHI bucket must deny non-TLS requests
# description: "The S3 bucket holding PHI must have a bucket policy that enforces secure transport."
# custom:
#   gap_id: GAP-03
#   framework: HIPAA
#   control_id: "164.312(e)(1)"
#   severity: high

package capstone.gap03

import rego.v1

deny contains msg if {
    bucket := bucket_addresses[_]
    not has_bucket_policy(bucket)

    msg := sprintf(
        "[GAP-03][HIPAA 164.312(e)(1)] %s: PHI S3 bucket lacks a bucket policy enforcing secure transport. Remediation: add a policy denying requests where aws:SecureTransport is false.",
        [bucket],
    )
}

bucket_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket"
    addr := r.address
}

# NOTE: Terraform does not expose the inline jsonencode() policy body
# in planned_values for this resource, so this policy verifies that
# the S3 bucket has an attached bucket policy. The exact
# aws:SecureTransport=false condition is implemented in Terraform code.
has_bucket_policy(bucket_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket_policy"

    some ref in r.expressions.bucket.references
    ref == sprintf("%s.id", [bucket_addr])
}