package capstone.gap08_test

import rego.v1
import data.capstone.gap08

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_apigatewayv2_stage.default",
                    "type": "aws_apigatewayv2_stage",
                    "expressions": {
                        "access_log_settings": [
                            {
                                "destination_arn": {
                                    "references": [
                                        "aws_cloudwatch_log_group.api.arn"
                                    ]
                                }
                            }
                        ]
                    }
                },
                {
                    "address": "aws_cloudwatch_log_group.api",
                    "type": "aws_cloudwatch_log_group"
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
                    "address": "aws_apigatewayv2_stage.default",
                    "type": "aws_apigatewayv2_stage",
                    "expressions": {}
                }
            ]
        }
    }
}

test_compliant_passes if {
    count(gap08.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
    some msg in gap08.deny with input as noncompliant_input
    contains(msg, "GAP-08")
    contains(msg, "164.312(b)")
    contains(msg, "aws_apigatewayv2_stage.default")
}