{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccountWideReadOnlyForAudit",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "eks:AccessKubernetesApi",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:ListBucket",
        "s3:ListAllMyBuckets",
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:DescribeTrails",
        "config:Get*",
        "config:Describe*",
        "config:List*",
        "securityhub:Get*",
        "securityhub:List*",
        "guardduty:Get*",
        "guardduty:List*",
        "access-analyzer:Get*",
        "access-analyzer:List*",
        "athena:GetQueryResults",
        "athena:StartQueryExecution",
        "athena:GetQueryExecution",
        "glue:GetTable",
        "glue:GetDatabase"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AccessAnalyzerCIEMWorkflow",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:StartPolicyGeneration",
        "access-analyzer:GetGeneratedPolicy",
        "access-analyzer:ListFindings",
        "access-analyzer:GetFinding"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowSSMSessionAccountWide",
      "Effect": "Allow",
      "Action": "ssm:StartSession",
      "Resource": [
        "arn:aws:ec2:*:${account_id}:instance/*",
        "arn:aws:ssm:*:${account_id}:document/SSM-SessionManagerRunShell"
      ]
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
      "Sid": "ExplicitDenyAllMutatingActions",
      "Effect": "Deny",
      "Action": [
        "ec2:Terminate*",
        "ec2:Stop*",
        "ec2:Reboot*",
        "ec2:Modify*",
        "ec2:Delete*",
        "ec2:Create*",
        "s3:Put*",
        "s3:Delete*",
        "iam:Put*",
        "iam:Delete*",
        "iam:Create*",
        "iam:Attach*",
        "iam:Detach*",
        "iam:Update*",
        "ssm:SendCommand",
        "config:Put*",
        "config:Delete*",
        "securityhub:Update*",
        "securityhub:BatchUpdate*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowIAMDatabaseAuthSecurityAuditor",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:*:${account_id}:dbuser:${db_resource_id}/security_auditor_readonly"
    }
  ]
}
