{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSAMLFederatedAssumption",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${account_id}:saml-provider/${saml_provider_name}"
      },
      "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
