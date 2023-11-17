resource "aws_iam_role" "sagemaker_execution" {
  name               = "${var.md_metadata.name_prefix}-execution"
  assume_role_policy = data.aws_iam_policy_document.sagemaker_assume_role.json

  managed_policy_arns = [
    aws_iam_policy.sagemaker_execution.arn
  ]
}

data "aws_iam_policy_document" "sagemaker_execution" {
  statement {
    sid       = "PassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["sagemaker.amazonaws.com"]
    }
  }
  statement {
    sid       = "ECRAccess"
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ecr:ListTagsForResource",
      "ecr:ListImages",
      "ecr:DescribeRepositories",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetLifecyclePolicy",
      "ecr:DescribeImageScanFindings",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:GetRepositoryPolicy"
    ]
  }
  statement {
    sid    = "KMSEncryption"
    effect = "Allow"
    resources = [
      module.kms.key_arn
    ]
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant"
    ]
  }
  statement {
    sid    = "CloudwatchLogsAccess"
    effect = "Allow"
    resources = [
      "arn:aws:logs:${var.vpc.specs.aws.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/sagemaker/**",
    ]
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:CreateLogGroup",
      "logs:DescribeLogStreams"
    ]
  }
  statement {
    sid       = "CloudwatchMetricsAccess"
    effect    = "Allow"
    resources = ["arn:aws:logs:${var.vpc.specs.aws.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/sagemaker/*"]
    actions = [
      "cloudwatch:PutMetricData"
    ]
  }
  statement {
    sid       = "EC2Access"
    effect    = "Allow"
    resources = ["arn:aws:ec2:${var.vpc.specs.aws.region}:${data.aws_caller_identity.current.account_id}:*/*"]
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DescribeVpcs",
      "ec2:DeleteNetworkInterface",
      "ecr:GetAuthorizationToken",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeDhcpOptions"
    ]
  }
  statement {
    sid       = "SageMakerAccess"
    effect    = "Allow"
    resources = ["arn:aws:sagemaker:${var.vpc.specs.aws.region}:${data.aws_caller_identity.current.account_id}:*/*"]
    actions = [
      "sagemaker:CreateModel",
      "sagemaker:CreateApp",
      "sagemaker:CreateEndpointConfig",
      "sagemaker:CreateEndpoint",
      "sagemaker:DeleteEndpoint",
      "sagemaker:DeleteEndpointConfig",
      "sagemaker:DescribeEndpointConfig",
      "sagemaker:DescribeEndpoint",
      "sagemaker:DescribeModel",
      "sagemaker:ListEndpointConfigs",
      "sagemaker:ListEndpoints",
      "sagemaker:ListModels",
      "sagemaker:UpdateEndpoint",
      "sagemaker:CreateTrainingJob",
      "sagemaker:DescribeTrainingJob",
      "sagemaker:StopTrainingJob",
      "sagemaker:CreateHyperParameterTuningJob",
      "sagemaker:DescribeHyperParameterTuningJob",
      "sagemaker:StopHyperParameterTuningJob",
      "sagemaker:CreateProcessingJob",
      "sagemaker:DescribeProcessingJob",
      "sagemaker:StopProcessingJob",
      "sagemaker:CreateTransformJob",
      "sagemaker:DescribeTransformJob",
      "sagemaker:StopTransformJob",
      "sagemaker:*"
    ]
  }
  statement {
    sid    = "S3ReadAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::jumpstart-cache-prod-${var.vpc.specs.aws.region}",
      "arn:aws:s3:::jumpstart-cache-prod-${var.vpc.specs.aws.region}/*"
    ]
  }
}

resource "aws_iam_policy" "sagemaker_execution" {
  name   = "${var.md_metadata.name_prefix}-execution"
  policy = data.aws_iam_policy_document.sagemaker_execution.json
}

data "aws_iam_policy_document" "sagemaker_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["sagemaker.amazonaws.com"]
    }
  }
}


resource "aws_iam_role_policy_attachment" "sagemaker_full_access" {
  role       = aws_iam_role.sagemaker_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_role_policy_attachment" "attach_s3_read_policy" {
  role       = aws_iam_role.sagemaker_execution.name
  policy_arn = var.s3_model_bucket.data.security.iam.read.policy_arn
}

resource "aws_iam_role_policy_attachment" "attach_s3_write_policy" {
  role       = aws_iam_role.sagemaker_execution.name
  policy_arn = var.s3_model_bucket.data.security.iam.write.policy_arn
}
