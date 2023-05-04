/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

# CloudWatch Event Rule to be triggered when a resource is shared with RAM
resource "aws_cloudwatch_event_rule" "rule_group_shared_event" {
  name        = "nf-supervisor-rule-group-shared"
  description = "Capture non-compliance of Network Firewall resources"

  event_pattern = <<EOF
{
  "source": [
    "aws.ram"
  ],
  "detail-type": [
    "Resource Sharing State Change"
  ]
}
EOF
}

# Trigger invoker Lambda function when resource is shared with RAM
resource "aws_cloudwatch_event_target" "trigger_evaluation" {
  rule      = aws_cloudwatch_event_rule.rule_group_shared_event.name
  target_id = "TriggerFirewallManagementEvaluation"
  arn       = module.invoker_lambda.lambda_function_arn
}
