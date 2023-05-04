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
import boto3
from botocore import exceptions

CROSS_ACCOUNT_ROLE_NAME = os.environ["CROSS_ACCOUNT_ROLE_NAME"]
CONFIG_RULE_NAME = os.environ["CONFIG_RULE_NAME"]

# Initiate logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(
    format="%(levelname)s %(threadName)s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.INFO,
)
logger.info("Lambda initialization completed")


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


def get_account_ids(organizations_client):
    """
    Constructs a list of all accounts in AWS Organization for evaluation

    Parameters:
        organizations_client: boto3 client for AWS Organizations

    Returns:
        account_ids (list): list of account IDs in AWS Organization
    """
    account_ids = []
    completed = False
    response = organizations_client.list_accounts()
    account_ids.extend(response["Accounts"])

    # Iterating through paginated results
    while completed == False:
        if "NextToken" in response:
            token = response["NextToken"]
            response = organizations_client.list_accounts(NextToken=token)
            account_ids.extend(response["Accounts"])
        else:
            completed = True

    return account_ids


def get_config_rule(spoke_config_client, account_id):
    """
    Finds the correct rule to trigger evaluation of in AWS Config.
    This is required since each account will have a unique Config rule ID appended to the name.

    Parameters:
        spoke_config_client: boto3 client for AWS Config in target AWS account

    Returns:
        rule_name (str): name of AWS Config rule to trigger
    """
    config_rule_list = []
    completed = False
    response = spoke_config_client.describe_config_rules()
    config_rule_list.extend(response["ConfigRules"])

    # Iterating through paginated results
    while completed == False:
        if "NextToken" in response:
            token = response["NextToken"]
            response = spoke_config_client.describe_config_rules(NextToken=token)
            config_rule_list.extend(response["ConfigRules"])
        else:
            completed = True

    # Identifying correct AWS Config rule to trigger
    for rule in config_rule_list:
        rule_name = rule["ConfigRuleName"]
        if CONFIG_RULE_NAME in rule_name:
            return rule_name
        else:
            logger.info("Unable to find Config rule in account: " + account_id)

    return


def trigger_evaluation(account_ids):
    """
    Triggers evaluation of AWS Config rule in each AWS account

    Parameters:
        account_ids (list): list of account IDs to trigger Config rule

    Returns:
        rule_name (str): name of AWS Config rule to trigger
    """

    for account in account_ids:
        id = account["Id"]

        try:
            # Initializing AWS Config client in each target account
            spoke_config_client = get_client("config", id)
        except exceptions.ClientError as e:
            error_message = e.response["Error"]["Message"]
            logger.error(error_message)
        else:
            # Getting correct AWS Config rule name and starting evaluation
            config_rule_name = get_config_rule(spoke_config_client, id)
            response = spoke_config_client.start_config_rules_evaluation(ConfigRuleNames=[config_rule_name])
            logger.info("Network Firewall evaluation started in account: " + id)


def handler(event, context):

    # Initializing AWS Organizations client
    organizations_client = boto3.client("organizations")

    # Getting account IDs for entire AWS Organization
    account_ids = get_account_ids(organizations_client)

    # Triggering AWS Config rule evaluation in all AWS accounts
    trigger_evaluation(account_ids)

    return
