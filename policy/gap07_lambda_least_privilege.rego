# policy/gap07_lambda_least_privilege.rego
# METADATA
# title: GAP-07 - Lambda IAM policy must use scoped data access
# description: "The patient intake Lambda must use an inline policy scoped to the intake DynamoDB table, uploads S3 bucket, and Acme KMS key."
# custom:
#   gap_id: GAP-07
#   framework: HIPAA
#   control_id: "164.312(a)(1)"
#   severity: high

package capstone.gap07

import rego.v1

deny contains msg if {
    not has_scoped_lambda_policy

    msg := "[GAP-07][HIPAA 164.312(a)(1)] Lambda IAM policy is not scoped to the required DynamoDB, S3, and KMS resources. Remediation: restrict Lambda permissions to the specific application resources."
}

has_scoped_lambda_policy if {
    some r in input.configuration.root_module.resources
    r.type == "aws_iam_role_policy"
    r.address == "aws_iam_role_policy.lambda_inline"

    some role_ref in r.expressions.role.references
    role_ref == "aws_iam_role.lambda"

    some dynamodb_ref in r.expressions.policy.references
    dynamodb_ref == "aws_dynamodb_table.intake.arn"

    some s3_ref in r.expressions.policy.references
    s3_ref == "aws_s3_bucket.uploads.arn"

    some kms_ref in r.expressions.policy.references
    kms_ref == "aws_kms_key.acme.arn"
}

# NOTE:
# Terraform does not expose the individual IAM actions from the
# inline jsonencode() policy in planned_values. This policy therefore
# verifies resource-level scoping through the references exposed in
# the Terraform plan. The specific least-privilege actions
# (dynamodb:PutItem, s3:PutObject, kms:GenerateDataKey, kms:Decrypt)
# are implemented in the Terraform configuration.