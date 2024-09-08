"""
Gets all RDS instances and cluster properties and post as
metrics to Datadog.

To run:
  python main.py
"""
import logging
import os
import sys
import time

import boto3
import click
import requests
from boto3.session import Session
from botocore.exceptions import ClientError
from credstash import getSecret
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

aws_account = os.environ["AWS_ACCOUNT"]
aws_service = "rds"
datadog_metric_name = "custom.aws.rds_properties"
datadog_url = "https://api.datadoghq.com/api/v1"
datadog_common_metric_tags = [
    "app:rds_properties_metrics",
    "domain:monitoring",
    "purpose:rds_properties_metrics",
    "repository:granular/shared-tooling/ce/datadog_custom_rds_properties_metrics",
    "source:gitlab-ci_schedule",
    "team:cloud-engineering",
]

# Configure root logger
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)

# Only log boto3 issues when CRITICAL.
boto3.set_stream_logger("botocore", logging.CRITICAL)


@click.command()
@click.option(
    "--post_to_datadog",
    required=True,
    default="no",
    help="'yes' to post metrics to Datadog or 'no' to not post metrics to Datadog.",
)
def main(post_to_datadog: str) -> None:
    """Run the code

    Args:
        post_to_datadog (str): yes or no to post metrics to Datadog.
    """
    regions_list = get_regions(aws_service)

    for region in regions_list:
        client = aws_api_client(aws_service, region)
        post_rds_instances_properties_metrics_to_datadog(
            aws_account, region, client, post_to_datadog
        )
        post_rds_clusters_properties_metrics_to_datadog(
            aws_account, region, client, post_to_datadog
        )


def aws_api_client(aws_service: str, region: str) -> object:
    """Get API client token.

    Args:
        aws_account (str): Account name, e.g, granappdevelopment
        region (str): Region name, e.g., us-east-1

    Returns:
        object: API client token for boto3.
    """
    try:
        api_session = boto3.Session(region_name=region)
        api_client = api_session.client(aws_service)
        return api_client

    except Exception as aws_api_client_error:
        logging.error(aws_api_client_error)


def post_rds_instances_properties_metrics_to_datadog(
    aws_account: str, region: str, client: object, post_to_datadog: str
) -> list:
    """Get RDS Instance properties.

    Args:
        aws_account (str): Account name, e.g, granappdevelopment
        region (str): Region name, e.g., us-east-1
        client (object): boto3 client.
        post_to_datadog (str): yes or no to post metrics to Datadog.
    """
    try:
        rds_type = "db_instance"
        paginator = client.get_paginator("describe_db_instances")
        response_iterator = paginator.paginate()
        for response in response_iterator:
            for instances in response["DBInstances"]:
                # Default maintenance variables
                has_maint = "no"
                maint_item = None
                maint_description = None
                maint_auto_applied_after_date = None
                maint_current_apply_date = None
                maint_forced_apply_date = None
                maint_status = None

                db_identifier = instances["DBInstanceIdentifier"]

                try:
                    db_name = instances["DBName"]
                except Exception:
                    db_name = "NO_DB_NAME_FOUND"

                db_parameter_group_list = instances["DBParameterGroups"]
                for db_group in db_parameter_group_list:
                    db_parameter_group = db_group["DBParameterGroupName"]

                db_instance_class = instances["DBInstanceClass"]
                engine = instances["Engine"]
                engine_version = instances["EngineVersion"]
                major_minor_engine_version = (
                    engine_version.split(".")[0] + "." + engine_version.split(".")[1]
                )
                instance_arn = instances["DBInstanceArn"]
                multi_az = instances["MultiAZ"]
                maint_window = instances["PreferredMaintenanceWindow"]
                app_tag = get_rds_tag(instance_arn, client, "app")
                repository_tag = get_rds_tag(instance_arn, client, "repository")
                slack_channel_tag = get_rds_tag(instance_arn, client, "slack_channel")
                teams_channel_tag = get_rds_tag(instance_arn, client, "teams_channel")
                team_tag = get_rds_tag(instance_arn, client, "team")
                victorops_routing_key_tag = get_rds_tag(
                    instance_arn, client, "victorops_routing_key"
                )
                automated_snapshots = get_db_instance_snaphosts(db_identifier, client)
                maintenance_actions = get_maintenance_actions(instance_arn, client)

                if maintenance_actions:
                    for action in maintenance_actions:
                        has_maint = "yes"
                        maint_item = action["Action"]
                        maint_description = action["Description"]

                        try:
                            maint_auto_applied_after_date = action[
                                "AutoAppliedAfterDate"
                            ]
                        except Exception:
                            pass

                        try:
                            maint_current_apply_date = action["CurrentApplyDate"]
                        except Exception:
                            pass

                        try:
                            maint_forced_apply_date = action["ForcedApplyDate"]
                        except Exception:
                            pass

                        if maint_current_apply_date and maint_auto_applied_after_date:
                            maint_status = "required"
                        else:
                            maint_status = "available"

                metric_tags = [
                    f"aws_account:{aws_account}",
                    f"aws_region:{region}",
                    f"db_identifier:{db_identifier}",
                    f"db_name:{db_name}",
                    f"rds_type:{rds_type}",
                    f"engine:{engine}",
                    f"engine_version:{engine_version}",
                    f"tag_app:{app_tag}",
                    f"tag_repository:{repository_tag}",
                    f"tag_slack_channel:{slack_channel_tag}",
                    f"tag_teams_channel:{teams_channel_tag}",
                    f"tag_team:{team_tag}",
                    f"tag_victorops_routing_key:{victorops_routing_key_tag}",
                    f"db_parameter_group:{db_parameter_group}",
                    f"db_instance_class:{db_instance_class}",
                    f"automated_snapshots:{automated_snapshots}",
                    f"multi_az:{multi_az}",
                    f"has_maint:{has_maint}",
                    f"maint_auto_applied_after_date:{maint_auto_applied_after_date}",
                    f"maint_current_apply_date:{maint_current_apply_date}",
                    f"maint_description:{maint_description}",
                    f"maint_forced_apply_date:{maint_forced_apply_date}",
                    f"maint_item:{maint_item}",
                    f"maint_status:{maint_status}",
                    f"maint_window:{maint_window}",
                ]
                joined_metric_tags = datadog_common_metric_tags + metric_tags

                post_metric_to_datadog(
                    post_to_datadog,
                    major_minor_engine_version,
                    joined_metric_tags,
                )

                notify_teams_for_maintenance(
                    maint_status,
                    victorops_routing_key_tag,
                    teams_channel_tag,
                    aws_account,
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        return error_code


def post_rds_clusters_properties_metrics_to_datadog(
    aws_account: str, region: str, client: object, post_to_datadog: str
) -> None:
    """Get RDS Cluster properties.

    Args:
        aws_account (str): Account name, e.g, granappdevelopment
        region (str): Region name, e.g., us-east-1
        client (object): boto3 client.
        post_to_datadog (str): yes or no to post metrics to Datadog.
    """
    try:
        rds_type = "db_cluster"
        paginator = client.get_paginator("describe_db_clusters")
        response_iterator = paginator.paginate()
        for response in response_iterator:
            for clusters in response["DBClusters"]:
                # Default maintenance variables
                has_maint = "no"
                maint_item = None
                maint_description = None
                maint_auto_applied_after_date = None
                maint_current_apply_date = None
                maint_forced_apply_date = None
                maint_status = None

                db_cluster_arn = clusters["DBClusterArn"]
                db_cluster_identifier = clusters["DBClusterIdentifier"]

                try:
                    db_name = clusters["DatabaseName"]
                except Exception:
                    db_name = "NO_CLUSTER_DB_NAME_FOUND"

                db_instance_class = "N/A"
                db_parameter_group = clusters["DBClusterParameterGroup"]
                engine = clusters["Engine"]
                engine_version = clusters["EngineVersion"]
                major_minor_engine_version = (
                    engine_version.split(".")[0] + "." + engine_version.split(".")[1]
                )
                multi_az = clusters["MultiAZ"]
                maint_window = clusters["PreferredMaintenanceWindow"]
                app_tag = get_rds_tag(db_cluster_arn, client, "app")
                repository_tag = get_rds_tag(db_cluster_arn, client, "repository")
                slack_channel_tag = get_rds_tag(db_cluster_arn, client, "slack_channel")
                teams_channel_tag = get_rds_tag(db_cluster_arn, client, "teams_channel")
                team_tag = get_rds_tag(db_cluster_arn, client, "team")
                victorops_routing_key_tag = get_rds_tag(
                    db_cluster_arn, client, "victorops_routing_key"
                )
                automated_snapshots = get_cluster_snaphosts(
                    db_cluster_identifier, client
                )

                maintenance_actions = get_maintenance_actions(db_cluster_arn, client)

                if maintenance_actions:
                    for action in maintenance_actions:
                        maint_item = action["Action"]
                        has_maint = "yes"
                        maint_description = action["Description"]

                        try:
                            maint_auto_applied_after_date = action[
                                "AutoAppliedAfterDate"
                            ]
                        except Exception:
                            pass

                        try:
                            maint_current_apply_date = action["CurrentApplyDate"]
                        except Exception:
                            pass

                        try:
                            maint_forced_apply_date = action["ForcedApplyDate"]
                        except Exception:
                            pass

                        if maint_current_apply_date and maint_auto_applied_after_date:
                            maint_status = "required"
                        else:
                            maint_status = "available"

                metric_tags = [
                    f"aws_account:{aws_account}",
                    f"aws_region:{region}",
                    f"db_identifier:{db_cluster_identifier}",
                    f"db_name:{db_name}",
                    f"rds_type:{rds_type}",
                    f"engine:{engine}",
                    f"engine_version:{engine_version}",
                    f"tag_app:{app_tag}",
                    f"tag_repository:{repository_tag}",
                    f"tag_slack_channel:{slack_channel_tag}",
                    f"tag_teams_channel:{teams_channel_tag}",
                    f"tag_team:{team_tag}",
                    f"tag_victorops_routing_key:{victorops_routing_key_tag}",
                    f"db_parameter_group:{db_parameter_group}",
                    f"db_instance_class:{db_instance_class}",
                    f"automated_snapshots:{automated_snapshots}",
                    f"multi_az:{multi_az}",
                    f"has_maint:{has_maint}",
                    f"maint_auto_applied_after_date:{maint_auto_applied_after_date}",
                    f"maint_current_apply_date:{maint_current_apply_date}",
                    f"maint_description:{maint_description}",
                    f"maint_forced_apply_date:{maint_forced_apply_date}",
                    f"maint_item:{maint_item}",
                    f"maint_status:{maint_status}",
                    f"maint_window:{maint_window}",
                ]
                joined_metric_tags = datadog_common_metric_tags + metric_tags

                post_metric_to_datadog(
                    post_to_datadog,
                    major_minor_engine_version,
                    joined_metric_tags,
                )

                notify_teams_for_maintenance(
                    maint_status,
                    victorops_routing_key_tag,
                    teams_channel_tag,
                    aws_account,
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        return error_code


def get_db_instance_snaphosts(db_identifier: str, client: object) -> bool:
    """Determine if instance has snapshots.

    Args:
        db_identifier (str): Instance identifier.
         client (object): boto3 client.

    Returns:
        bool: True/False
    """
    paginator = client.get_paginator("describe_db_snapshots")
    response_iterator = paginator.paginate(
        DBInstanceIdentifier=db_identifier, SnapshotType="automated"
    )
    for response in response_iterator:
        db_snapshots = response["DBSnapshots"]
        if db_snapshots:
            return True
        return False


def get_cluster_snaphosts(db_cluster_identifier: str, client: object) -> bool:
    """Determine if cluster has snapshots.

    Args:
        db_cluster_identifier (str): Cluster identifier.
        client (object): AWS boto3 client token.

    Returns:
        bool: True/False
    """
    paginator = client.get_paginator("describe_db_cluster_snapshots")
    response_iterator = paginator.paginate(
        DBClusterIdentifier=db_cluster_identifier, SnapshotType="automated"
    )
    for response in response_iterator:
        db_cluster_snapshots = response["DBClusterSnapshots"]
        if db_cluster_snapshots:
            return True
        return False


def get_maintenance_actions(rds_arn: str, client: object) -> list:
    """Get maintenance actions for RDS instance or cluster.

    Args:
        rds_arn (str): RDS instance or cluster ARN.
         client (object): boto3 client.

    Returns:
        list: List of RDS maintenance actions.
    """
    paginator = client.get_paginator("describe_pending_maintenance_actions")
    response_iterator = paginator.paginate(ResourceIdentifier=rds_arn)
    for response in response_iterator:
        for maintenance_action in response["PendingMaintenanceActions"]:
            return maintenance_action["PendingMaintenanceActionDetails"]


def get_rds_tag(rds_arn: str, client: object, tag_name: str) -> str:
    """Get RDS instance specific tag value, e.g., cloud-engineering for team tag.

    Args:
        rds_arn (str): DB instance or cluster ARN.
         client (object): boto3 client.
        tag_name (str): Tag name to search to get its value.

    Returns:
        str: Tag value.
    """
    response = client.list_tags_for_resource(ResourceName=rds_arn)
    tags = response["TagList"]
    tag_value = f"{tag_name}_TAG_NOT_FOUND"
    if tags:
        for tag in response["TagList"]:
            if tag.get("Key").lower() == f"{tag_name}":
                tag_value = tag["Value"]
    return tag_value


def get_regions(service_name: str) -> list:
    """Get list of all regions for an AWS service.

    Args:
        service_name (str): AWS service name, e.g., rds

    Returns:
        list: List of regions for the AWS service.
            Example: [ "us-east-1", "us-east-2", "us-west-1" ]
    """
    s = Session()
    regions_list = s.get_available_regions(service_name)
    return regions_list


def post_metric_to_datadog(
    post_to_datadog: str,
    metric_value: str,
    metric_tags: str,
) -> None:
    """Post metrics to Datadog depending if 'post_to_datadog'
    is set to 'yes' or 'no'.

    Args:
        post_to_datadog (str): 'yes' or 'no' to post metrics to Datadog.
        metric_value (str): Value of the metric.
        metric_tags (str): Tags to post on the metric.
    """
    datadog_api_key = getSecret("datadog.cloudeng.apikey", region="us-east-1")
    datadog_url_params = {"api_key": datadog_api_key}
    epoch_now_time = int(time.time())

    body = {
        "series": [
            {
                "metric": datadog_metric_name,
                "points": [[f"{epoch_now_time}", f"{metric_value}"]],
                "tags": metric_tags,
                "type": "gauge",
            }
        ]
    }
    # Post metric to Datadog only if the post_to_datadog is yes.
    if post_to_datadog == "yes":
        response = requests.post(
            f"{datadog_url}/series", params=datadog_url_params, json=body
        )

        if response.status_code != 202:
            logging.error(
                f"Unable to post RDS properties metrics to Datadog with body: {body}"
            )
            sys.exit(1)

    logging.info(body)


def notify_teams_for_maintenance(
    maint_status, victorops_routing_key_tag, teams_channel_tag, aws_account
):
    valid_teams_channel_tag = teams_channel_tag.find("TAG_NOT_FOUND")
    valid_victorops_routing_key_tag = victorops_routing_key_tag.find("TAG_NOT_FOUND")

    aws_account = aws_account

    # If 'teams_channel_tag' or 'victorops_routing_key_tag' have a valid value for the key,
    # and the maintenance status is 'available', then send out the notification.
    if maint_status == "available":
        if valid_teams_channel_tag == -1 or valid_victorops_routing_key_tag == -1:
            logging.info("To be notified.")
            # print(teams_channel_tag)  # Send notification to this channel.
        else:
            logging.info(
                "Tags teams_channel_tag and victorops_routing_key_tag missing. Not sending out notification."
            )
            # print("Tags teams_channel_tag and victorops_routing_key_tag missing. Not sending out notification.")
    else:
        logging.info("No active maintenance available to notify about.")
        # print("No maintenance available to notify about.")


def post_maint_notification_to_slack():
    """Send a notification through slack for RDS maintenance.

    Args:

    """
    # Call the chat.postMessage method using the WebClient
    SLACK_TOKEN = "your-slack-token"

    client = WebClient(token=SLACK_TOKEN)
    try:
        response = client.chat_postMessage(
            channel="#rds-maintenance-notifications",
            text="WARNING:The database is going under maintenance.",
        )
        print("Message sent: ", response["ts"])
    except SlackApiError as e:
        print("Error sending message: {}".format(e))


def send_maint_notification_by_email():
    """Send an email notification through SNS for RDS maintenance.

    Args:

    """
    sns = boto3.client("sns", region_name="us-east-1")

    # Create a new SNS topic if it doesn't exist already
    topic_name = "MySNSTopic"

    # Create an SNS topic
    response = sns.create_topic(Name=topic_name)

    # Extract the ARN (Amazon Resource Name) of the newly created topic
    topic_arn = response["TopicArn"]

    # Define the email subject and message
    subject = "RDS instances under maintenance."
    notification = "This is to notify that the RDS instance is under maintenance."

    response = sns.publish(TopicArn=topic_arn, Subject=subject, Message=notification)
    print(response)

    print(f"MessageId: {response['MessageId']}")


if __name__ == "__main__":
    main()
