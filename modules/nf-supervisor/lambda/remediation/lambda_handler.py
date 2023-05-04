# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import os
import logging
import json
import boto3
from botocore import exceptions

# Initiate logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(
    format="%(levelname)s %(threadName)s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.INFO,
)
logger.info("Lambda initialization completed")

# Obtaining relevant Lambda environment variables
CROSS_ACCOUNT_ROLE_NAME = os.environ["CROSS_ACCOUNT_ROLE_NAME"]


def get_client(service, account_id):
    """
    Gets boto3 client after assuming the Config role in the target AWS account

    Parameters:
        service (str): the identifier of the AWS service to create a client for
        account_id (str): the AWS account ID to assume role in

    Returns:
        boto3 client: a boto3 client object
    """

    # Constructing role ARN from account ID and role name
    role_arn = "arn:aws:iam::" + account_id + ":role/" + CROSS_ACCOUNT_ROLE_NAME

    # Obtaining credentials by assuming role
    sts_client = boto3.client("sts")
    credentials = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")["Credentials"]

    return boto3.client(
        service,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_ou_path(organizations_client, account_id):
    """
    Constructs the full OU path of the target account

    Parameters:
        organizations_client: boto3 client for AWS Organizations
        account_id (str): the target AWS account ID

    Returns:
        ou_path (str): the full OU path of the target account
    """

    ou_path = ""
    type = ""

    # Looping through all levels of the Organization until complete path os obtained
    while type != "ROOT":
        response = organizations_client.list_parents(ChildId=account_id)
        ou_id = response["Parents"][0]["Id"]
        type = response["Parents"][0]["Type"]

        if type != "ROOT":
            ou_name = organizations_client.describe_organizational_unit(OrganizationalUnitId=ou_id)[
                "OrganizationalUnit"
            ]["Name"]
            account_id = ou_id
            ou_path = "/" + ou_name + ou_path
            response = organizations_client.list_parents(ChildId=account_id)
            type = response["Parents"][0]["Type"]

    # Constructing full OU path using root OU name
    root_name = organizations_client.list_roots()["Roots"][0]["Name"]
    ou_path = "/" + root_name + ou_path

    logger.info("Starting Network Firewall remediation for account: " + account_id + " in OU: " + ou_path)

    return ou_path


def get_rule_group_mapping(ssm_client, spoke_ou_path, account_id):
    """
    Obtains the rule group mapping containing each rule group to apply to OU

    Parameters:
        ssm_client: boto3 client for AWS Systems Manager in the central security account
        spoke_ou_path (str): the full OU path of the target account
        account_id (str): the target AWS account ID

    Returns:
        mapping (dict): raw mapping of OU to rule group
    """

    # Reading SSM parameter containing rule groups to apply to the OU
    try:
        response = ssm_client.get_parameter(Name=spoke_ou_path)
    except ssm_client.exceptions.ParameterNotFound:
        mapping = "None"
        logger.info("No mapping found for OU path: " + spoke_ou_path + ". Evaluation skipped.")
    else:
        ou_baseline_mapping = json.loads(response["Parameter"]["Value"])

        # Iterating through SSM parameter and obtaining mapping for target account
        for account, rules in ou_baseline_mapping.items():
            if (account == "all_accounts" and account_id not in ou_baseline_mapping.keys()) or account == account_id:
                mapping = rules
                return mapping

    return


def get_rule_group_arns(raw_mapping):
    """
    Obtains the ARNs of each rule group to apply to each policy

    Parameters:
        raw_mapping: raw mapping of OU to rule group

    Returns:
        mapping (dict): mapping of required rule group types to rule group ARNs
    """

    processed_mapping = {}

    for rule_group_type, rule_group_list in raw_mapping.items():
        if rule_group_type not in processed_mapping:
            processed_mapping[rule_group_type.upper()] = []

        for rule_group_arn in rule_group_list:
            if rule_group_type.upper() == "STATEFUL" and type(rule_group_list) is list:
                processed_mapping[rule_group_type.upper()].append({"ResourceArn": rule_group_arn})
            else:
                processed_mapping[rule_group_type.upper()].append(
                    {
                        "ResourceArn": rule_group_arn,
                        "Priority": rule_group_list[rule_group_arn],
                    }
                )

    logger.info("Obtained the following firewall rule group mapping: " + json.dumps(processed_mapping))

    return processed_mapping


def remediate_rule_order(
    strict_order,
    policy,
    evaluation,
    result_token,
    spoke_anf_client,
    spoke_config_client,
):
    """
    Remediates non-compliant policies in the account if strict ordering is required.
    This function creates a new firewall policy with the correct rule order, and associates it with any firewalls in the account.

    Parameters:
        policy: description of AWS Network Firewall policy to be modified
        spoke_anf_client: boto3 client for AWS Network Firewall in the target account
        strict_order (str): whether or not to apply strict ordering to policy
    """

    policy_name = policy["Name"]
    spoke_policy = spoke_anf_client.describe_firewall_policy(FirewallPolicyName=policy_name)
    spoke_policy_details = spoke_policy["FirewallPolicy"]
    resource_arn = spoke_policy["FirewallPolicyResponse"]["FirewallPolicyArn"]
    rule_order = spoke_policy_details["StatefulEngineOptions"]["RuleOrder"]
    remediated_policy_name = None

    # Checking if policy has the correct stateful rule order, and modifying if not
    if strict_order == "true" and rule_order == "DEFAULT_ACTION_ORDER":
        # Getting details of existing policy for creation of new policy
        policy_arn = spoke_policy["FirewallPolicyResponse"]["FirewallPolicyArn"]
        description = (
            spoke_policy["FirewallPolicyResponse"]["Description"]
            if "Description" in spoke_policy["FirewallPolicyResponse"]
            else "Policy created by central firewall management"
        )
        tags = (
            spoke_policy["FirewallPolicyResponse"]["Tags"]
            if spoke_policy["FirewallPolicyResponse"]["Tags"] != []
            else [{"Key": "Name", "Value": policy_name}]
        )
        encryption_config = spoke_policy["FirewallPolicyResponse"]["EncryptionConfiguration"]
        remediated_policy_name = policy_name + "-baselined"

        # Setting rule order to strict, and removing all stateful rule groups from policy (these are not compatible with strict ordering)
        spoke_policy_details["StatefulEngineOptions"]["RuleOrder"] = "STRICT_ORDER"
        spoke_policy_details["StatefulEngineOptions"]["StreamExceptionPolicy"] = "DROP"
        spoke_policy_details["StatefulRuleGroupReferences"] = []

        # Creating new policy with strict rule ordering, as rule ordering on an existing policy cannot be modified
        try:
            response = spoke_anf_client.create_firewall_policy(
                FirewallPolicyName=remediated_policy_name,
                FirewallPolicy=spoke_policy_details,
                Description=description,
                Tags=tags,
                EncryptionConfiguration=encryption_config,
            )
        except exceptions.ClientError as e:
            logger.error("Could not create a new policy with strict rule ordering: " + remediated_policy_name)
            logger.error(e)
        else:
            remediated_policy_arn = response["FirewallPolicyResponse"]["FirewallPolicyArn"]
            logger.info("Created new policy with strict rule ordering: " + remediated_policy_name)

        # Updating firewalls in the account to associate the remediated firewall policy with
        firewall_list = spoke_anf_client.list_firewalls()["Firewalls"]
        for firewall in firewall_list:
            firewall_arn = firewall["FirewallArn"]
            spoke_firewall = spoke_anf_client.describe_firewall(FirewallArn=firewall_arn)
            update_token = spoke_firewall["UpdateToken"]

            if spoke_firewall["Firewall"]["FirewallPolicyArn"] == policy_arn:
                try:
                    response = spoke_anf_client.associate_firewall_policy(
                        UpdateToken=update_token,
                        FirewallArn=firewall_arn,
                        FirewallPolicyArn=remediated_policy_arn,
                    )
                except exceptions.ClientError as e:
                    logger.error(
                        "Could not associate remediated policy with strict rule ordering on following firewall: "
                        + firewall_arn
                    )
                    logger.error(e)
                else:
                    logger.info(
                        "Successfully associated remediated policy "
                        + remediated_policy_name
                        + " with firewall: "
                        + firewall_arn
                    )

        # Deleting non-compliant firewall policy
        try:
            response = spoke_anf_client.delete_firewall_policy(FirewallPolicyName=policy_name)
        except exceptions.ClientError as e:
            logger.error("Could not delete non-compliant firewall policy: " + policy_name)
            logger.error(e)
        else:
            logger.info("Deleted non-compliant firewall policy: " + policy_name)

            # If remediation is successful, reporting to AWS Config
            put_new_evaluation(
                spoke_config_client,
                evaluation,
                resource_arn,
                result_token,
            )

    return remediated_policy_name


def reprioritise_rule_groups(strict_order, rule_group_mapping, rule_group_list):
    """
    Modifies priority of existing rule groups to ensure baseline rule groups are evaluated first

    Parameters:
        rule_group_mapping (dict): mapping of baseline rule groups to apply to policy
        rule_group_list: list of current rule groups attached to policy
        strict_order (str): whether or not to apply strict ordering to policy

    Returns:
        rule_group_list (list): list of reprioritised rule groups
    """

    # Obtaining the maximum priority of baseline rule groups
    if strict_order == "true":
        priority_list = []
        for rule_group in rule_group_mapping:
            priority_list.append(int(rule_group["Priority"]))

            # Checking that priority of baseline rule groups is correct
            rule_group_list[:] = [x for x in rule_group_list if x["ResourceArn"] != rule_group["ResourceArn"]]

        max_baseline_priority = max(priority_list)
        min_priority = min(rule_group_list, key=lambda x: x["Priority"]) if len(rule_group_list) > 0 else 0

        # Increasing the priority of each existing rule group by the max baseline rule group, thus avoiding priority conflicts
        if min_priority != 0 and min_priority["Priority"] <= max_baseline_priority:
            delta = max_baseline_priority - min_priority["Priority"] + 1
            for i in range(len(rule_group_list)):
                rule_group_list[i]["Priority"] += delta

    return rule_group_list


def remediate_baseline_rule_groups(
    event,
    policy_list,
    strict_order,
    rule_group_mapping,
    spoke_config_client,
    spoke_anf_client,
):
    """
    Remediates non-compliant policies in the account if baseline rule groups are not applied

    Parameters:
        event: invoking event
        spoke_anf_client: boto3 client for AWS Network Firewall in the target account
        spoke_config_client: boto3 client for AWS Config in the target account
        rule_group_mapping (dict): mapping of baseline rule groups to apply to policy
        strict_order (str): whether or not to apply strict ordering to policy

    Returns:
        modified_resources (list): list of remediated resources
    """

    evaluations_list = event["Evaluations"]
    result_token = event["ResultToken"]
    modified_resources = []

    # Looping through non-compliant firewall policies to apply the correct baseline rule groups
    for evaluation in evaluations_list:
        resource_name = evaluation["ComplianceResourceId"]
        resource_type = evaluation["ComplianceResourceType"]
        compliance = evaluation["ComplianceType"]

        if compliance == "NON_COMPLIANT":
            for policy in policy_list:

                # Modifying rule order if required
                remediated_policy_name = remediate_rule_order(
                    strict_order,
                    policy,
                    evaluation,
                    result_token,
                    spoke_anf_client,
                    spoke_config_client,
                )
                if remediated_policy_name is None:
                    policy_name = policy["Name"]
                else:
                    policy_name = remediated_policy_name

                resource_name = "policy/" + policy_name
                spoke_policy = spoke_anf_client.describe_firewall_policy(FirewallPolicyName=policy_name)
                update_token = spoke_policy["UpdateToken"]
                spoke_policy_details = spoke_policy["FirewallPolicy"]

                if "STATEFUL" in rule_group_mapping:
                    # Reprioritising rule groups to enforce baseline rule groups first
                    stateful_rule_group_list = reprioritise_rule_groups(
                        strict_order,
                        rule_group_mapping["STATEFUL"],
                        spoke_policy_details["StatefulRuleGroupReferences"],
                    )

                    stateful_rule_group_list.extend(rule_group_mapping["STATEFUL"])

                    # Removing duplicate rule groups
                    unique_stateful_rules = [dict(t) for t in {tuple(d.items()) for d in stateful_rule_group_list}]

                    spoke_policy_details["StatefulRuleGroupReferences"] = unique_stateful_rules

                if "STATELESS" in rule_group_mapping:
                    # Reprioritising rule groups to enforce baseline rule groups first
                    stateless_rule_group_list = reprioritise_rule_groups(
                        strict_order,
                        rule_group_mapping["STATELESS"],
                        spoke_policy_details["StatelessRuleGroupReferences"],
                    )

                    stateless_rule_group_list.extend(rule_group_mapping["STATELESS"])

                    # Removing duplicate rule groups
                    unique_stateless_rules = [
                        dict(t)
                        for t in {tuple(d.items()) for d in spoke_policy_details["StatelessRuleGroupReferences"]}
                    ]

                    spoke_policy_details["StatelessRuleGroupReferences"] = unique_stateless_rules
                try:
                    response = spoke_anf_client.update_firewall_policy(
                        FirewallPolicyName=policy_name,
                        FirewallPolicy=spoke_policy_details,
                        UpdateToken=update_token,
                    )
                except exceptions.ClientError as e:
                    logger.error("Could not add rule groups to non-compliant policy: " + resource_name)
                    logger.error(e)
                else:
                    resource_arn = response["FirewallPolicyResponse"]["FirewallPolicyArn"]

                    # If remediation is successful, reporting to AWS Config
                    put_new_evaluation(
                        spoke_config_client,
                        evaluation,
                        resource_arn,
                        result_token,
                    )

                    # Creating list of modified firewall policies
                    modified_resources.append({"ResourceArn": resource_arn, "ResourceType": resource_type})

    return modified_resources


def remediate_all_rule_groups(
    event,
    policy_list,
    strict_order,
    rule_group_mapping,
    spoke_config_client,
    spoke_anf_client,
):
    """
    Remediates non-compliant policies in the account if excess rule groups are attached to a policy that are not centrally defined

    Parameters:
        event: invoking event
        spoke_anf_client: boto3 client for AWS Network Firewall in the target account
        spoke_config_client: boto3 client for AWS Config in the target account
        rule_group_mapping (dict): mapping of rule groups to apply to policy
        strict_order (str): whether or not to apply strict ordering to policy

    Returns:
        modified_resources (list): list of remediated resources
    """

    evaluations_list = event["Evaluations"]
    result_token = event["ResultToken"]
    modified_resources = []

    # Looping through non-compliant firewall policies to apply the correct baseline rule groups
    for evaluation in evaluations_list:
        resource_name = evaluation["ComplianceResourceId"]
        resource_type = evaluation["ComplianceResourceType"]
        compliance = evaluation["ComplianceType"]

        if compliance == "NON_COMPLIANT":
            for policy in policy_list:
                # Modifying rule order if required
                remediated_policy_name = remediate_rule_order(
                    strict_order,
                    policy,
                    evaluation,
                    result_token,
                    spoke_anf_client,
                    spoke_config_client,
                )

                if remediated_policy_name is None:
                    policy_name = policy["Name"]
                else:
                    policy_name = remediated_policy_name

                policy_name = policy["Name"]
                resource_name = "policy/" + policy_name
                spoke_policy = spoke_anf_client.describe_firewall_policy(FirewallPolicyName=policy_name)
                update_token = spoke_policy["UpdateToken"]
                spoke_policy_details = spoke_policy["FirewallPolicy"]

                if "STATEFUL" in rule_group_mapping:
                    spoke_policy_details["StatefulRuleGroupReferences"] = rule_group_mapping["STATEFUL"]

                if "STATELESS" in rule_group_mapping:
                    spoke_policy_details["StatelessRuleGroupReferences"] = rule_group_mapping["STATELESS"]

                try:
                    response = spoke_anf_client.update_firewall_policy(
                        FirewallPolicyName=policy_name,
                        FirewallPolicy=spoke_policy_details,
                        UpdateToken=update_token,
                    )
                except exceptions.ClientError as e:
                    logger.error("Could not enforce rule groups on non-compliant policy: " + resource_name)
                    logger.error(e)
                else:
                    resource_arn = response["FirewallPolicyResponse"]["FirewallPolicyArn"]

                    # If remediation is successful, reporting to AWS Config
                    put_new_evaluation(
                        spoke_config_client,
                        evaluation,
                        resource_arn,
                        result_token,
                    )

                    # Creating list of modified firewall policies
                    modified_resources.append({"ResourceArn": resource_arn, "ResourceType": resource_type})

                    logger.info("Successfully enforced centrally defined rule groups on policy: " + resource_name)

    return modified_resources


def put_new_evaluation(spoke_config_client, evaluation, resource_id, result_token):
    """
    Reports new evaluations to AWS Config after non-compliant resources have been remediated

    Parameters:
        evaluation (dict): original resource evaluations to modify
        spoke_anf_client: boto3 client for AWS Config in the target account
        resource_id: ID of resource that was remediated
        result_token (str): AWS Config results token

    Returns:
        eval_cc (dict): resource evalations for AWS Config
    """

    evaluation["ComplianceType"] = "COMPLIANT"
    evaluation["Annotation"] = resource_id

    response = spoke_config_client.put_evaluations(ResultToken=result_token, Evaluations=[evaluation])

    return response


def handler(event, context):
    account_id = event["accountId"]

    # Obtaining required boto3 clients
    spoke_anf_client = get_client("network-firewall", account_id)
    spoke_config_client = get_client("config", account_id)
    ssm_client = boto3.client("ssm")
    organizations_client = boto3.client("organizations")
    spoke_ou_path = get_ou_path(organizations_client, account_id)

    # Reading SSM parameter to obtain raw rule group mapping
    raw_rule_group_mapping = get_rule_group_mapping(ssm_client, spoke_ou_path, account_id)

    # Reads whether or not to enforce baselines only, then removing from rule group mapping
    baseline_only = raw_rule_group_mapping["baseline_only"]
    del raw_rule_group_mapping["baseline_only"]

    # Reads whether or not to enforce strict order, then removing from rule group mapping
    strict_order = raw_rule_group_mapping["strict_order"]
    del raw_rule_group_mapping["strict_order"]

    # Obtaining ARNs of firewall rule groups for mapping
    processed_rule_group_mapping = get_rule_group_arns(raw_rule_group_mapping)

    # Get list of all firewall policies in target account
    policy_list = spoke_anf_client.list_firewall_policies()["FirewallPolicies"]

    # Remediating all firewall policies
    if baseline_only == "true":
        modified_resources = remediate_baseline_rule_groups(
            event,
            policy_list,
            strict_order,
            processed_rule_group_mapping,
            spoke_config_client,
            spoke_anf_client,
        )
    else:
        modified_resources = remediate_all_rule_groups(
            event,
            policy_list,
            strict_order,
            processed_rule_group_mapping,
            spoke_config_client,
            spoke_anf_client,
        )

    logger.info(
        "The following resources were modified in account " + account_id + ": " + json.dumps(modified_resources)
    )

    return
