terraform {
  required_version = ">= 1.0"
}

data "aws_caller_identity" "caller" {
}
