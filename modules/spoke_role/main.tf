# Get region
data "aws_region" "current" {}

# Allowing Network Firewall manager lambda functions in central security account to assume role
data "aws_iam_policy_document" "nf_supervisor_execution_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }

    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${var.security_account_id}:role/nf-supervisor-*"]
    }
  }
}

# Allowing access to Network Firewall, AWS Config and Logs
data "aws_iam_policy_document" "nf_supervisor_execution_policy" {
  statement {
    actions = [
      "network-firewall:Describe*",
      "network-firewall:List*",
      "network-firewall:UpdateFirewallPolicy*",
      "network-firewall:CreateFirewallPolicy",
      "network-firewall:DeleteFirewallPolicy",
      "network-firewall:AssociateFirewallPolicy",
      "network-firewall:TagResource",
      "network-firewall:UntagResource"
    ]

    resources = ["*"]
  }

  statement {
    actions = [
      "config:PutEvaluations",
      "config:GetComplianceDetailsByConfigRule",
      "config:StartConfigRulesEvaluation",
      "config:DescribeConfigRules"
    ]

    resources = ["*"]
  }

  statement {
    actions = [
      "logs:ListLogDeliveries",
      "logs:GetLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:CreateLogDelivery"
    ]

    resources = ["*"]
  }
}

# Attaching inline policy to role
resource "aws_iam_role_policy" "nf_supervisor_execution_attachment" {
  name   = "nf-supervisor-policy"
  role   = aws_iam_role.nf_supervisor_execution_role.name
  policy = data.aws_iam_policy_document.nf_supervisor_execution_policy.json
}

# Creating role for assumption by Network Firewall manager Lambda functions in central security account
resource "aws_iam_role" "nf_supervisor_execution_role" {
  name               = "nf-supervisor-execution-role-${data.aws_region.current.name}"
  description        = "Role for use by central security account for Network Firewall management"
  assume_role_policy = data.aws_iam_policy_document.nf_supervisor_execution_trust_policy.json
}

