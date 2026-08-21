{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyRDSVisibility",
      "Effect": "Allow",
      "Action": [
        "rds:Describe*",
        "rds:ListTagsForResource",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics",
        "logs:GetLogEvents",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowIAMDatabaseAuthDbAdmin",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:${account_id}:dbuser:${db_resource_id}/db_admin"
    }
  ]
}
