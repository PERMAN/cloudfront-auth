terraform {
  required_version = ">= 1.0"
  required_providers {
    archive = {
      source = "hashicorp/archive"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.77.0"
    }
  }
}

data "aws_caller_identity" "caller" {
}
