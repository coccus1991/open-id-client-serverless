terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.74.0"
    }
  }
}

provider "aws" {
  region = var.region
  shared_credentials_file = var.shared_credentials_file
  default_tags {
      tags = var.tags
  }
}