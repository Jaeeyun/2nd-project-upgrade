{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InheritOpsGeneralReadOnly",
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
        "ssm:DescribeInstanceInformation",
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
      "Sid": "ApplyApprovedChangesTempUntilCIEMCycle",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateTags",
        "ec2:ModifyInstanceAttribute",
        "ssm:SendCommand"
      ],
      "Resource": "arn:aws:ec2:*:${account_id}:instance/*"
    },
    {
      "Sid": "SendCommandScopedDocumentsOnly",
      "Effect": "Allow",
      "Action": "ssm:SendCommand",
      "Resource": "arn:aws:ssm:*:${account_id}:document/MyOrg-*"
    },
    {
      "Sid": "TriggerSecurityHubCustomActionsOpsLead",
      "Effect": "Allow",
      "Action": [
        "securityhub:Get*",
        "securityhub:List*",
        "securityhub:BatchUpdateFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowIAMDatabaseAuthOpsLead",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:${account_id}:dbuser:${db_resource_id}/approver_readonly"
    }
  ]
}
