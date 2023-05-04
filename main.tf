/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

# Deploy central AWS Network Firewall Supervisor infrastructure
module "nf_supervisor" {
  source                  = "./modules/nf-supervisor"
  remediate               = var.remediate
  cross_account_role_name = var.cross_account_role_name
}

# SSM parameter for each rule group to OU mapping, for the evaluation and remediation Lambda functions to read
resource "aws_ssm_parameter" "rule_group_OU_mapping" {
  for_each  = local.rule_group_mappings
  name      = each.key
  type      = "String"
  value     = jsonencode(each.value)
  overwrite = true
}
