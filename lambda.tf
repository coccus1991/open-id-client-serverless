module "create_role_lambda" {
  source  = "registry.terraform.io/terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 4"

  create_role = true

  role_name         = var.lambda_role_name
  role_requires_mfa = false

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]

  custom_role_trust_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "lambda.amazonaws.com",
                    "edgelambda.amazonaws.com"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

module "open_id_client_serverless_lambda" {
  source  = "registry.terraform.io/terraform-aws-modules/lambda/aws"
  version = "2.34.0"
  function_name = var.lambda_function_name
  handler = "app.lambdaHandler"
  runtime = "nodejs14.x"
  source_path = "${path.module}/src"
  lambda_role = "${module.create_role_lambda.iam_role_arn}"
  create_role = false
  publish = true
}