terraform {
  required_version = ">= 1.0"
  required_providers {
    archive = {
      source = "hashicorp/archive"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    template = {
      source = "hashicorp/template"
    }
  }
}

data "aws_caller_identity" "caller" {
}
