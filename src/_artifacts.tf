resource "massdriver_artifact" "domain" {
  field                = "domain"
  provider_resource_id = aws_sagemaker_domain.main.arn
  name                 = "AWS SageMaker Domain: ${aws_sagemaker_domain.main.domain_name}"
  artifact = jsonencode(
    {
      data = {
        infrastructure = {
          domain_arn = aws_sagemaker_domain.main.arn
          user_arn = aws_sagemaker_user_profile.main.arn
        }
        security = {
          iam = {
            execution = {
              policy_arn = aws_iam_policy.sagemaker_execution.arn
            }
          }
        }
      }
    }
  )
}
