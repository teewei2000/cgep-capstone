# policy/gap08_api_logging.rego
# METADATA
# title: GAP-08 - API Gateway must have access logging enabled
# description: "The patient intake API Gateway stage must send access logs to a CloudWatch log group."
# custom:
#   gap_id: GAP-08
#   framework: HIPAA
#   control_id: "164.312(b)"
#   severity: medium

package capstone.gap08

import rego.v1

deny contains msg if {
    stage := stage_addresses[_]
    not has_access_logging(stage)

    msg := sprintf(
        "[GAP-08][HIPAA 164.312(b)] %s: API Gateway access logging is not configured. Remediation: configure access_log_settings with a CloudWatch log group destination.",
        [stage],
    )
}

stage_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_apigatewayv2_stage"
    addr := r.address
}

# Check API Gateway stage exists
# Check access_log_settings exists
# Its destination points to CloudWatch log group
has_access_logging(stage_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_apigatewayv2_stage"
    r.address == stage_addr

    some log_config in r.expressions.access_log_settings

    some destination_ref in log_config.destination_arn.references
    destination_ref == "aws_cloudwatch_log_group.api.arn"
}