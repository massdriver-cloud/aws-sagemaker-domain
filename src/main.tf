locals {
  private_subnet_ids = [for subnet in var.vpc.data.infrastructure.private_subnets : element(split("/", subnet["arn"]), 1)]
  vpc_id             = element(split("/", var.vpc.data.infrastructure.arn), 1)
}
resource "aws_sagemaker_domain" "main" {
  domain_name = "${var.md_metadata.name_prefix}-domain"
  auth_mode   = "IAM"
  vpc_id      = local.vpc_id
  subnet_ids  = local.private_subnet_ids
  retention_policy {
    home_efs_file_system = var.efs.retention_policy
  }

  default_user_settings {
    execution_role = aws_iam_role.sagemaker_execution.arn
  }
}

resource "aws_sagemaker_user_profile" "main" {
  domain_id         = aws_sagemaker_domain.main.id
  user_profile_name = "${var.md_metadata.name_prefix}-user"
  user_settings {
    execution_role  = aws_iam_role.sagemaker_execution.arn
    security_groups = [aws_security_group.sagemaker_user.id]
  }
}
