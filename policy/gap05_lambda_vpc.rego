# policy/gap05_lambda_vpc.rego
# METADATA
# title: GAP-05 - Lambda PHI workload must run in a VPC
# description: "The patient intake Lambda must be attached to private subnets and a security group."
# custom:
#   gap_id: GAP-05
#   framework: HIPAA
#   control_id: "164.312(e)(1)"
#   severity: high

package capstone.gap05

import rego.v1

deny contains msg if {
    lambda := lambda_addresses[_]
    not has_vpc_config(lambda)

    msg := sprintf(
        "[GAP-05][HIPAA 164.312(e)(1)] %s: Lambda function is not attached to a VPC. Remediation: configure vpc_config with private subnets and a security group.",
        [lambda],
    )
}

lambda_addresses contains addr if {
    some r in input.configuration.root_module.resources
    r.type == "aws_lambda_function"
    addr := r.address
}

# check vpc_config exists
# check subnet references the private subnet
# check security_group_ids = [aws_security_group.lambda.id]
has_vpc_config(lambda_addr) if {
    some r in input.configuration.root_module.resources
    r.type == "aws_lambda_function"
    r.address == lambda_addr

    some vpc in r.expressions.vpc_config

    some subnet_ref in vpc.subnet_ids.references
    startswith(subnet_ref, "aws_subnet.private")

    some sg_ref in vpc.security_group_ids.references
    startswith(sg_ref, "aws_security_group.")
}