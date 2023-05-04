/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

locals {
  rule_group_mappings = {
    "/Root" = {
      "all_accounts" = {
        "baseline_only" = "true"
        "strict_order"  = "true"
        "STATEFUL" = {
          "${aws_networkfirewall_rule_group.deny_all.arn}" = 20
        },
        "STATELESS" = {
          "${aws_networkfirewall_rule_group.allow_https.arn}" = 200
        }
      },
      "12345678910" = {
        "baseline_only" = "true"
        "strict_order"  = "true"
        "STATEFUL" = {
          "${aws_networkfirewall_rule_group.deny_all.arn}" = 10
        },
        "STATELESS" = {
          "${aws_networkfirewall_rule_group.allow_https.arn}" = 100
        }
      }
    }
  }
}
