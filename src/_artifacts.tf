# resource "massdriver_artifact" "domain" { #TODO: change to sagemaker
#   field                = "domain"
#   provider_resource_id = aws_sagemaker_domain.main.arn
#   name                 = "AWS SageMaker Domain: ${aws_sagemaker_domain.main.domain_name}"
#   artifact = jsonencode(
#     {
#       data = {
#         infrastructure = {
#           domain_arn = aws_sagemaker_domain.main.arn
#           user_arn = aws_sagemaker_user_profile.main.arn
#         }
#         security = {
#           iam = {
#             execution_role = {
#               role_arn = aws_iam_role.sagemaker_execution.arn
#             }
#           }
#         }
#       }
#     }
#   )
# }
