resource "null_resource" "cloudfront-auth" {
  provisioner "local-exec" {
    command     = "./build.sh"
    working_dir = path.module
    environment = {
      CLOUDFRONT_URL   = var.cloudfront_url
      CLIENT_ID        = var.client_id
      CLIENT_SECRET    = var.client_secret
      ISSUER           = var.issuer
      AUTHZ_ENDPOINT   = var.authz_endpoint
      TOKEN_ENDPOINT   = var.token_endpoint
      JWKS_URI         = var.jwks_uri
      SESSION_DURATION = var.session_duration
      ENCRYPT_KEY      = var.encrypt_key
    }
  }
}

data "archive_file" "cloudfront-auth" {
  depends_on  = [null_resource.cloudfront-auth]
  type        = "zip"
  source_dir  = "${path.module}/app"
  output_path = "${path.module}/cloudfront-auth.zip"
}

data "template_file" "cloudfront-auth" {
  template = file("${path.module}/policy/cloudfront-auth.json")

  vars = {
    account_id = data.aws_caller_identity.caller.account_id
  }
}

resource "aws_iam_role" "cloudfront-auth" {
  name               = "cloudfront-auth"
  assume_role_policy = file("${path.module}/policy/assume_role_policy.json")
}

resource "aws_iam_role_policy" "cloudfront-auth" {
  role   = aws_iam_role.cloudfront-auth.name
  policy = data.template_file.cloudfront-auth.rendered
}

resource "aws_lambda_function" "cloudfront-auth" {
  filename      = data.archive_file.cloudfront-auth.output_path
  function_name = "cloudfront-auth"
  handler       = "index.handler"
  timeout       = 5
  role          = aws_iam_role.cloudfront-auth.arn

  runtime = "nodejs14.x"
  publish = true
}