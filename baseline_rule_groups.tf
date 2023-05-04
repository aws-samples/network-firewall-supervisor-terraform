/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

###################### Example Stateful Rule Group ######################

# Sharing stateful rule group to organization using RAM
resource "aws_ram_resource_association" "stateful_rule_group_assoc" {
  resource_arn       = aws_networkfirewall_rule_group.deny_all.arn
  resource_share_arn = module.nf_supervisor.ram_share_arn
}

# Stateful firewall rule group, with strict ordering, that denies all traffic
resource "aws_networkfirewall_rule_group" "deny_all" {
  name     = "deny-all"
  type     = "STATEFUL"
  capacity = 100
  rule_group {
    rules_source {
      stateful_rule {
        action = "DROP"
        header {
          direction        = "FORWARD"
          protocol         = "IP"
          destination      = "ANY"
          destination_port = "ANY"
          source_port      = "ANY"
          source           = "ANY"
        }
        rule_option {
          keyword = "sid:1"
        }
      }
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}


###################### Example Stateless Rule Group ######################


# Sharing stateless rule group to organization using RAM
resource "aws_ram_resource_association" "stateless_rule_group_assoc" {
  resource_arn       = aws_networkfirewall_rule_group.allow_https.arn
  resource_share_arn = module.nf_supervisor.ram_share_arn
}

# Stateless firewall rule group, that allows 443 TCP traffic from specified IPs
resource "aws_networkfirewall_rule_group" "allow_https" {
  name     = "stateless-allow-https"
  type     = "STATELESS"
  capacity = 100
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              source {
                address_definition = "1.2.3.4/32"
              }
              source_port {
                from_port = 443
                to_port   = 443
              }
              destination {
                address_definition = "124.1.1.5/32"
              }
              destination_port {
                from_port = 443
                to_port   = 443
              }
              protocols = [6]
              tcp_flag {
                flags = ["SYN"]
                masks = ["SYN", "ACK"]
              }
            }
          }
        }
      }
    }
  }
}
