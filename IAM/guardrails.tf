resource "aws_iam_policy" "guardrails" {
  name        = "Guardrails"
  path        = "/"
  description = "Deny ability to delete data and key resources"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Deny",
            "Action": [
                "ec2:TerminateInstances",
                "elasticache:DeleteUser",
                "dynamodb:DeleteItem",
                "s3:DeleteObjectVersion",
                "elasticache:DeleteCacheCluster",
                "rds:DeleteDBSnapshot",
                "kms:DeleteImportedKeyMaterial",
                "dynamodb:DeleteTable",
                "s3:DeleteBucketPolicy",
                "kms:DisableKey",
                "ssm:DeleteParameters",
                "ec2:DeleteVolume",
                "ssm:DeleteParameter",
                "kms:DeleteCustomKeyStore",
                "cloudfront:DeleteCachePolicy",
                "route53:DeleteHostedZone",
                "s3:DeleteObject",
                "cloudfront:DeleteDistribution",
                "dynamodb:DeleteBackup",
                "s3:DeleteBucket",
                "rds:DeleteDBCluster",
                "kms:DeleteAlias",
                "rds:DeleteDBInstance"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}