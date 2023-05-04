/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

# Get region
data "aws_region" "current" {}

# Get AWS Organization
data "aws_organizations_organization" "current" {}

# AWS Config Organization custom rule to track compliance of firewall resources
resource "aws_config_organization_custom_rule" "network_firewall_config_rule" {
  lambda_function_arn  = module.evaluation_lambda.lambda_function_arn
  name                 = "CheckFirewallCompliance"
  trigger_types        = ["ConfigurationItemChangeNotification"]
  resource_types_scope = ["AWS::NetworkFirewall::FirewallPolicy"]

  depends_on = [
    aws_lambda_permission.remediation_permission,
    aws_lambda_permission.evaluation_permission,
  ]
}

# Creating Lambda function used to evaluate compliance of resources
module "evaluation_lambda" {
  source                            = "terraform-aws-modules/lambda/aws"
  function_name                     = "nf_supervisor_evaluation_${data.aws_region.current.name}"
  handler                           = "evaluation/lambda_handler.handler"
  runtime                           = "python3.9"
  source_path                       = "${path.module}/lambda"
  cloudwatch_logs_retention_in_days = 30
  memory_size                       = 128
  timeout                           = 120
  hash_extra                        = "nf_supervisor_evaluation_${data.aws_region.current.name}" # https://github.com/terraform-aws-modules/terraform-aws-lambda/issues/204
  create_role                       = false
  lambda_role                       = aws_iam_role.nf_supervisor_lambda_role.arn

  environment_variables = {
    REMEDIATION_LAMBDA_NAME = module.remediation_lambda.lambda_function_name
    REMEDIATE               = var.remediate,
    CROSS_ACCOUNT_ROLE_NAME = "${var.cross_account_role_name}-${data.aws_region.current.name}"
  }
}

# Creating Lambda function used to remediate non-compliant resources
module "remediation_lambda" {
  source                            = "terraform-aws-modules/lambda/aws"
  function_name                     = "nf_supervisor_remediation_${data.aws_region.current.name}"
  handler                           = "remediation/lambda_handler.handler"
  runtime                           = "python3.9"
  source_path                       = "${path.module}/lambda"
  cloudwatch_logs_retention_in_days = 30
  memory_size                       = 128
  timeout                           = 900
  hash_extra                        = "nf_supervisor_remediation_${data.aws_region.current.name}" # https://github.com/terraform-aws-modules/terraform-aws-lambda/issues/204
  create_role                       = false
  lambda_role                       = aws_iam_role.nf_supervisor_lambda_role.arn

  environment_variables = {
    CROSS_ACCOUNT_ROLE_NAME = "${var.cross_account_role_name}-${data.aws_region.current.name}"
  }
}

# Creating Lambda function to invoke Config evaluation when a rule is shared
module "invoker_lambda" {
  source                            = "terraform-aws-modules/lambda/aws"
  function_name                     = "nf_supervisor_invoker_${data.aws_region.current.name}"
  handler                           = "invoker/lambda_handler.handler"
  runtime                           = "python3.9"
  source_path                       = "${path.module}/lambda"
  cloudwatch_logs_retention_in_days = 30
  memory_size                       = 128
  timeout                           = 120
  hash_extra                        = "nf_supervisor_invoker_${data.aws_region.current.name}" # https://github.com/terraform-aws-modules/terraform-aws-lambda/issues/204
  create_role                       = false
  lambda_role                       = aws_iam_role.invoker_lambda_role.arn

  environment_variables = {
    CROSS_ACCOUNT_ROLE_NAME = "${var.cross_account_role_name}-${data.aws_region.current.name}"
    CONFIG_RULE_NAME        = "${aws_config_organization_custom_rule.network_firewall_config_rule.name}"
  }
}

# Allowing AWS Config to invoke evaluation lambda
resource "aws_lambda_permission" "evaluation_permission" {
  action        = "lambda:InvokeFunction"
  function_name = module.evaluation_lambda.lambda_function_arn
  principal     = "config.amazonaws.com"
  statement_id  = "AllowExecutionFromConfig"
}

# Allowing AWS Config to invoke evaluation lambda
resource "aws_lambda_permission" "evaluation_multiaccount_config_permission" {
  action        = "lambda:InvokeFunction"
  function_name = module.evaluation_lambda.lambda_function_arn
  principal     = "config-multiaccountsetup.amazonaws.com"
  statement_id  = "AllowExecutionFromConfigMultiAccount"
}

# Allowing evaluation lambda to invoke evaluation lambda
resource "aws_lambda_permission" "remediation_permission" {
  action        = "lambda:InvokeFunction"
  function_name = module.remediation_lambda.lambda_function_arn
  principal     = "lambda.amazonaws.com"
  source_arn    = module.evaluation_lambda.lambda_function_arn
  statement_id  = "AllowExecutionFromEvaluationLambda"
}

# Allowing CloudWatch Events to invoke evaluation lambda
resource "aws_lambda_permission" "invoker_permission" {
  action        = "lambda:InvokeFunction"
  function_name = module.invoker_lambda.lambda_function_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rule_group_shared_event.arn
  statement_id  = "AllowExecutionFromCloudWatchEvents"
}

# Create RAM share for firewall resources
resource "aws_ram_resource_share" "rule_group_share" {
  name                      = "nf-supervisor-rule-group-share"
  allow_external_principals = false
}

# Associating firewall RAM share with organization
resource "aws_ram_principal_association" "org_assoc" {
  principal          = data.aws_organizations_organization.current.arn
  resource_share_arn = aws_ram_resource_share.rule_group_share.arn
}
