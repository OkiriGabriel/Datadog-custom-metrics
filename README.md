# Summary

This project produces all RDS instance and cluster properties and posts as a custom metric to Datadog. Examples of these properties are engine version, upcoming maintenance, tags, etc.

All of this data is used to display on [this Datadog dashboard](https://corteva.datadoghq.com/dashboard/62m-thy-564/rds-maintenance-list?from_ts=1658418228428&to_ts=1658504628428&live=true).

---

## What data does this gather

This will gather properties from RDS instances and clusters from all AWS acccounts and regions and will post this data to a `custom.aws.rds_properties` Datadog metric.  You can view all the tags posted to this metric by looking at the `"tags":` in the `post_metric_to_datadog` function from the [src/main.py](https://gitlab.internal.granular.ag/granular/shared-tooling/ce/datadog_custom_rds_properties_metrics/-/blob/main/src/main.py) file.

---

## Running the code

Below are two ways to run the code.

### Running in Gitlab CI

This is designed to mainly run in GitLab CI once a day using the [GitLab CI pipeline schedule](https://gitlab.internal.granular.ag/granular/shared-tooling/ce/datadog_custom_rds_properties_metrics/-/pipeline_schedules). However, below are the other ways it can/will be ran.

- Manually running the `default` branch pipeline [here](https://gitlab.internal.granular.ag/granular/shared-tooling/ce/datadog_custom_rds_properties_metrics/-/pipelines/new).

### Running locally

You can run this locally by doing the following.  You will need python3.9 to run locally.

1. Log into an AWS account, e.g., granappdevelopment, with at least <AWS_ACCOUNT_NAME>/Maintenance access via [assume](https://us.dev.insights.granular.ag/eng-portal/docs/getting-started/aws-setup) CLI so it can retrieve CredStash values.
2. Setup python3.9 virtualenv.

    ```make setup```

3. Run one of the make commands below depending on if you want to post metrics.
   - `make run_no_post_datadog`: This will not post metrics to Datadog.
   - `make run_post_datadog`: This will post metrics to Datadog.

---

## Troubleshooting

If this pipeline is failing, then check the Job output for noticeable errors.  This could be due to issues connecting to either the AWS API using boto3 or Datadog API using the Datadog API key.
