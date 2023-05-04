/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0 */

variable "remediate" {
  type        = string
  default     = "true"
  description = "If the custom firewall manager solution should remediate non-compliant resources"
}

variable "cross_account_role_name" {
  type        = string
  description = "Cross-account role for evaluation, remediation, and invoker lambda functions to assume"
}
