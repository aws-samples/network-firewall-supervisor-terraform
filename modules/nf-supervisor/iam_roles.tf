/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

############### IAM role for remediation/evaluation Lambda functions ###############

# Allowing Lambda to assume role
data "aws_iam_policy_document" "nf_supervisor_lambda_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Defining inline policy for remediation/evaluation role
data "aws_iam_policy_document" "nf_supervisor_lambda_policy" {
  statement {
    actions = [
      "cloudwatch:PutMetricData",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = ["*"]
  }

  statement {
    actions   = ["sts:AssumeRole"]
    resources = ["*"]
  }

  statement {
    actions   = ["ssm:GetParameter"]
    resources = ["*"]
  }

  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = ["${module.remediation_lambda.lambda_function_arn}"]
  }

  statement {
    actions   = ["network-firewall:DescribeRuleGroup"]
    resources = ["*"]
  }

  statement {
    actions = [
      "organizations:DescribeOrganizationalUnit",
      "organizations:ListParents",
      "organizations:ListRoots"
    ]

    resources = ["*"]
  }
}

# Attaching inline policy to role
resource "aws_iam_role_policy" "nf_supervisor_lambda_policy" {
  name   = "nf-supervisor-lambda-policy"
  role   = aws_iam_role.nf_supervisor_lambda_role.name
  policy = data.aws_iam_policy_document.nf_supervisor_lambda_policy.json
}

# Creating role for remediation/evaluation Lambda functions
resource "aws_iam_role" "nf_supervisor_lambda_role" {
  name               = "nf-supervisor-lambda-role-${data.aws_region.current.name}"
  description        = "Role for use by Network Firewall manager Lambda functions"
  assume_role_policy = data.aws_iam_policy_document.nf_supervisor_lambda_trust_policy.json
}


############### IAM role for Invoker Lambda ###############

# Attaching inline policy to role
resource "aws_iam_role_policy" "invoker_lambda_policy" {
  name   = "invoker-lambda-policy"
  role   = aws_iam_role.invoker_lambda_role.name
  policy = data.aws_iam_policy_document.invoker_lambda_policy.json
}

# Creating role for invoker Lambda function
resource "aws_iam_role" "invoker_lambda_role" {
  name               = "${var.cross_account_role_name}-${data.aws_region.current.name}"
  description        = "Role for use by Network Firewall manager invoker Lambda function"
  assume_role_policy = data.aws_iam_policy_document.nf_supervisor_lambda_trust_policy.json
}

# Defining inline policy for invoker role
data "aws_iam_policy_document" "invoker_lambda_policy" {
  statement {
    actions = [
      "cloudwatch:PutMetricData",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = ["*"]
  }

  statement {
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/${var.cross_account_role_name}"]
  }

  statement {
    actions = [
      "organizations:ListAccounts",
      "network-firewall:DescribeRuleGroup"
    ]
    resources = ["*"]
  }
}

