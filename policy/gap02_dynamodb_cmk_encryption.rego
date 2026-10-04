# policy/gap02_dynamodb_cmk_encryption.rego
# METADATA
# title: GAP-02 - DynamoDB PHI table must use customer-managed KMS encryption
# description: "Every DynamoDB table holding PHI must use server-side encryption with a customer-managed KMS key."
# custom:
#   gap_id: GAP-02
#   framework: HIPAA
#   control_id: "164.312(a)(2)(iv)"
#   severity: high

package capstone.gap02

import rego.v1

deny contains msg if {
    table := table_addresses[_]
    not has_customer_kms_encryption(table)

    msg := sprintf(
        "[GAP-02][HIPAA 164.312(a)(2)(iv)] %s: PHI DynamoDB table lacks customer-managed KMS encryption. Remediation: enable server-side encryption with the Acme Health CMK.",
        [table],
    )
}

table_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_dynamodb_table"
    addr := r.address
}

# Terraform may not expose the resolved kms_key_arn in planned_values
# when the KMS key is created in the same plan. Check configuration
# references to confirm the DynamoDB table is configured to use a CMK.
# Lesson learned: Don't assume every Terraform attribute will be available as a resolved value in planned_values.
# For some controls, we will need planned_values (what Terraform plans to create)
# Configuration (what Terraform configuration explicitly references)
has_customer_kms_encryption(table_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_dynamodb_table"
    r.address == table_addr

    some encryption in r.expressions.server_side_encryption
    encryption.enabled.constant_value == true

    some ref in encryption.kms_key_arn.references
    startswith(ref, "aws_kms_key.")
}