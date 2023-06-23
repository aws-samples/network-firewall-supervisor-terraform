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
REMEDIATION_LAMBDA_NAME = os.environ["REMEDIATION_LAMBDA_NAME"]
REMEDIATE = os.environ["REMEDIATE"]


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

    logger.info("Starting Network Firewall evaluation for account: " + account_id + " in OU: " + ou_path)

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


def evaluate_baseline_rule_groups(policy_list, strict_order, rule_group_mapping, spoke_anf_client):
    """
    Evaluates compliance of policies in the account, checks if baseline rule groups are applied

    Parameters:
        policy_list (list): list of AWS Network Firewall policies in the target account
        strict_order (str): whether or not to apply strict ordering to policy
        spoke_anf_client: boto3 client for AWS Network Firewall in the target account
        rule_group_mapping (dict): mapping of baseline rule groups to apply to policy

    Returns:
        results (list): list of compliant and non-compliant resources
    """

    results = []

    # Looping through all firewall policies in the account to check if they have baseline firewall rule groups attached
    for policy in policy_list:
        policy_name = policy["Name"]
        resource_name = "policy/" + policy_name

        spoke_policy = spoke_anf_client.describe_firewall_policy(FirewallPolicyName=policy_name)
        spoke_policy_details = spoke_policy["FirewallPolicy"]
        rule_order = spoke_policy_details["StatefulEngineOptions"]["RuleOrder"]

        if rule_group_mapping != "None":
            compliant = True

            # Checking if required stateful rules are attached to firewall policy
            if "STATEFUL" in rule_group_mapping and not all(
                arn in spoke_policy_details["StatefulRuleGroupReferences"] for arn in rule_group_mapping["STATEFUL"]
            ):
                compliant = False

            # Checking if required stateless rules are attached to firewall policy
            if "STATELESS" in rule_group_mapping and not all(
                arn in spoke_policy_details["StatelessRuleGroupReferences"] for arn in rule_group_mapping["STATELESS"]
            ):
                compliant = False

            # Checking if policy has the correct stateful rule order
            if strict_order == "true" and rule_order == "DEFAULT_ACTION_ORDER":
                compliant = False

            # Contructing evaluation statuses to report to AWS Config
            if compliant == True:
                results.append(
                    {
                        "Compliance": "COMPLIANT",
                        "Resource_type": "AWS::NetworkFirewall::FirewallPolicy",
                        "Resource": resource_name,
                        "Annotation": spoke_policy["FirewallPolicyResponse"]["FirewallPolicyArn"],
                    }
                )
            else:
                results.append(
                    {
                        "Compliance": "NON_COMPLIANT",
                        "Resource_type": "AWS::NetworkFirewall::FirewallPolicy",
                        "Resource": resource_name,
                        "Annotation": "Does not match central definition (Missing Rule Group/s)",
                    }
                )
                logger.info("The firewall policy : " + resource_name + " does not have the required rule groups")

    return results


def evaluate_all_rule_groups(policy_list, strict_order, rule_group_mapping, spoke_anf_client):
    """
    If: baseline_plus = false
    Evaluates compliance of policies in the account, checks if excess rule groups are attached to a policy that are not centrally defined

    Parameters:
        policy_list (list): list of AWS Network Firewall policies in the target account
        strict_order (str): whether or not to apply strict ordering to policy
        spoke_anf_client: boto3 client for AWS Network Firewall in the target account
        rule_group_mapping (dict): mapping of baseline rule groups to apply to policy

    Returns:
        results (list): list of compliant and non-compliant resources
    """

    results = []

    # Looping through all firewall policies in the account to check if they have any excess rule groups attached
    for policy in policy_list:
        policy_name = policy["Name"]
        resource_name = "policy/" + policy_name

        spoke_policy = spoke_anf_client.describe_firewall_policy(FirewallPolicyName=policy_name)
        spoke_policy_details = spoke_policy["FirewallPolicy"]
        rule_order = spoke_policy_details["StatefulEngineOptions"]["RuleOrder"]

        if rule_group_mapping != "None":
            compliant = True

            # Checking if there are no excess stateful rules
            if (
                "STATEFUL" in rule_group_mapping
                and spoke_policy_details["StatefulRuleGroupReferences"] != rule_group_mapping["STATEFUL"]
            ):
                compliant = False

            # Checking if there are no excess stateless rules
            if (
                "STATELESS" in rule_group_mapping
                and spoke_policy_details["StatelessRuleGroupReferences"] != rule_group_mapping["STATELESS"]
            ):
                compliant = False

            # Checking if policy has the correct stateful rule order
            if strict_order == "true" and rule_order == "DEFAULT_ACTION_ORDER":
                compliant = False

            # Contructing evaluation statuses to report to AWS Config
            if compliant == True:
                results.append(
                    {
                        "Compliance": "COMPLIANT",
                        "Resource_type": "AWS::NetworkFirewall::FirewallPolicy",
                        "Resource": resource_name,
                        "Annotation": spoke_policy["FirewallPolicyResponse"]["FirewallPolicyArn"],
                    }
                )
            else:
                results.append(
                    {
                        "Compliance": "NON_COMPLIANT",
                        "Resource_type": "AWS::NetworkFirewall::FirewallPolicy",
                        "Resource": resource_name,
                        "Annotation": "Does not match central definition (Missing Rule Group/s)",
                    }
                )
                logger.info("The firewall policy : " + resource_name + " does not have the required rule groups")

    return results


# Generates a dict for evaluations in the required format for Config
def build_evaluation(resource_id, compliance_type, event, resource_type, annotation):
    """
    Generates evaluations in the required format for AWS Config

    Parameters:
        resource_id (str): ID of resource being evaluated
        compliance_type (str): compliance status of resource being evaluated
        event: invoking event
        resource_type (str): type of AWS resource being evaluated
        annotation (str): additional note to apply to Config evaluation

    Returns:
        eval_cc (dict): resource evalations for AWS Config
    """

    eval_cc = {}

    if annotation is not None:
        eval_cc["Annotation"] = annotation
    eval_cc["ComplianceResourceType"] = resource_type
    eval_cc["ComplianceResourceId"] = resource_id
    eval_cc["ComplianceType"] = compliance_type
    eval_cc["OrderingTimestamp"] = str(json.loads(event["invokingEvent"])["notificationCreationTime"])

    return eval_cc


# Invoke remediation lambda if enabled
def invoke_remediation(remediation_lambda_name, evaluations, account_id, config_rule_name, result_token):
    """
    Invokes the remediation Lambda function if remediation is enabled

    Parameters:
        remediation_lambda_name (str): name of remediation Lambda function
        evaluations (dict): resource evaluations to pass to AWS Config
        account_id (str): the account ID of the target AWS account
        config_rule_name (str): the name of AWS Config rule to report results to
        result_token (str): AWS Config results token
    """
    remediation_event = {}
    remediation_event["accountId"] = account_id
    remediation_event["Evaluations"] = evaluations
    remediation_event["ConfigRuleName"] = config_rule_name
    remediation_event["ResultToken"] = result_token

    lambda_client = boto3.client("lambda")
    try:
        response = lambda_client.invoke(
            FunctionName=remediation_lambda_name,
            InvocationType="Event",
            Payload=json.dumps(remediation_event),
        )
    except exceptions.ClientError as e:
        logger.error("Could not invoke remediation Lambda function")
        logger.error(e)
    else:
        logger.info("Invoked remediation Lambda function successfully")

    return response


def handler(event, context):
    account_id = event["accountId"]
    config_rule_name = event["configRuleName"]
    result_token = event["resultToken"]
    evaluations = []

    # Initialising the required boto3 clients
    spoke_config_client = get_client("config", account_id)
    spoke_anf_client = get_client("network-firewall", account_id)
    ssm_client = boto3.client("ssm")
    organizations_client = boto3.client("organizations")
    spoke_ou_path = get_ou_path(organizations_client, account_id)

    # Reading SSM parameter to obtain raw rule group mapping
    raw_rule_group_mapping = get_rule_group_mapping(ssm_client, spoke_ou_path, account_id)

    # Reads whether or not to enforce baselines only, then removing from rule group mapping
    baseline_plus = raw_rule_group_mapping["baseline_plus"]
    del raw_rule_group_mapping["baseline_plus"]

    # Reads whether or not to enforce strict order, then removing from rule group mapping
    strict_order = raw_rule_group_mapping["strict_order"]
    del raw_rule_group_mapping["strict_order"]

    # Obtaining ARNs of firewall rule groups for mapping
    processed_rule_group_mapping = get_rule_group_arns(raw_rule_group_mapping)

    # Get list of all firewall policies in target account
    policy_list = spoke_anf_client.list_firewall_policies()["FirewallPolicies"]

    # Evaluating all firewall policies
    if baseline_plus == "true":
        results = evaluate_baseline_rule_groups(
            policy_list, strict_order, processed_rule_group_mapping, spoke_anf_client
        )
    else:
        results = evaluate_all_rule_groups(policy_list, strict_order, processed_rule_group_mapping, spoke_anf_client)

    # Building evaluations in correct format for AWS Config
    for resource in results:
        evaluations.append(
            build_evaluation(
                resource["Resource"],
                resource["Compliance"],
                event,
                resource["Resource_type"],
                resource["Annotation"],
            )
        )

    try:
        # Reporting evaluation findings to AWS Config
        response = spoke_config_client.put_evaluations(Evaluations=evaluations, ResultToken=event["resultToken"])
    except exceptions.ClientError as e:
        logger.error("Could not push evaluation results to AWS Config")
        logger.error(e)
    else:
        logger.info("Evaluation results pushed to AWS Config successfully!")

    print(evaluations)

    # Invoking remediation Lambda function if required
    if REMEDIATE == "true":
        invoke_remediation(
            REMEDIATION_LAMBDA_NAME,
            evaluations,
            account_id,
            config_rule_name,
            result_token,
        )

    return response
