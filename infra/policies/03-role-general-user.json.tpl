{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyBroadVisibility",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:ListAllMyBuckets",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics",
        "logs:GetLogEvents",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstanceProperties",
        "ssm:DescribeSessions",
        "ssm:GetConnectionStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowSSMSessionAnyInstance",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": "arn:aws:ec2:*:${account_id}:instance/*"
    },
    {
      "Sid": "AllowSSMSessionDocument",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": "arn:aws:ssm:*:${account_id}:document/SSM-SessionManagerRunShell"
    },
    {
      "Sid": "DenyNonStandardSSMDocuments",
      "Effect": "Deny",
      "Action": "ssm:StartSession",
      "NotResource": [
        "arn:aws:ec2:*:${account_id}:instance/*",
        "arn:aws:ssm:*:${account_id}:document/SSM-SessionManagerRunShell"
      ]
    },
    {
      "Sid": "TerminateOwnSSMSessionsOnly",
      "Effect": "Allow",
      "Action": ["ssm:TerminateSession", "ssm:ResumeSession"],
      "Resource": "arn:aws:ssm:*:${account_id}:session/$${aws:userid}-*"
    },
    {
      "Sid": "AllowOpenDataChannelOwnSessionOnly",
      "Effect": "Allow",
      "Action": "ssmmessages:OpenDataChannel",
      "Resource": "arn:aws:ssm:*:*:session/$${aws:userid}-*"
    },
    {
      "Sid": "BaselineOperationalActionsTempUntilCIEMCycle",
      "Effect": "Allow",
      "Action": [
        "ec2:RebootInstances",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "arn:aws:ec2:*:${account_id}:instance/*"
    },
    {
      "Sid": "AllowIAMDatabaseAuthOpsGeneral",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:${account_id}:dbuser:${db_resource_id}/general_user_readonly"
    }
  ]
}
