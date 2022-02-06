variable "region" {
  default = "us-east-1"
}

variable "shared_credentials_file" {
  type = string
  default = "~/.aws/credentials"
}

variable "tags" {
  type = map(string)
  default = {}
}

variable "lambda_function_name" {
  type = string
  default = "open_id_client_serverless"
}

variable "lambda_role_name" {
  type = string
  default = "open_id_client_role"
}