# policy/gap04_s3_versioning.rego
# METADATA
# title: GAP-04 - S3 PHI bucket must have versioning enabled
# description: "Every S3 bucket holding PHI must have versioning enabled to support recovery from accidental deletion or modification."
# custom:
#   gap_id: GAP-04
#   framework: HIPAA
#   control_id: "164.308(a)(7)"
#   severity: medium

package capstone.gap04

import rego.v1

deny contains msg if {
    bucket := bucket_addresses[_]
    not has_versioning_enabled(bucket)

    msg := sprintf(
        "[GAP-04][HIPAA 164.308(a)(7)] %s: S3 bucket does not have versioning enabled. Remediation: enable S3 versioning.",
        [bucket],
    )
}

bucket_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket"
    addr := r.address
}

# S3 doesn't have versioning → aws_s3_bucket_versioning.uploads with status = "Enabled"
has_versioning_enabled(bucket_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_s3_bucket_versioning"

    some ref in r.expressions.bucket.references
    references_bucket(ref, bucket_addr)

    some config in r.expressions.versioning_configuration
    config.status.constant_value == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])