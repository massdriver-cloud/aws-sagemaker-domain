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
    resources = ["*"]
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
    resources = ["*"]
    actions = [
      "cloudwatch:PutMetricData"
    ]
  }
  statement {
    sid       = "EC2Access"
    effect    = "Allow"
    resources = ["*"]
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
    resources = ["*"]
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

resource "aws_iam_role_policy_attachment" "attach_s3_read_policy" {
  role       = aws_iam_role.sagemaker_execution.name
  policy_arn = var.s3_model_bucket.data.security.iam.read.policy_arn
}

resource "aws_iam_role_policy_attachment" "attach_s3_write_policy" {
  role       = aws_iam_role.sagemaker_execution.name
  policy_arn = var.s3_model_bucket.data.security.iam.write.policy_arn
}