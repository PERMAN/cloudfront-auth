resource "null_resource" "cloudfront-auth" {
  triggers = {
    # define version number
    version = "1.0.0" // Updating this value will cause it to run again
  }
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

resource "aws_iam_role" "cloudfront-auth" {
  name               = var.function_name
  assume_role_policy = file("${path.module}/policy/assume_role_policy.json")
}

resource "aws_iam_role_policy" "cloudfront-auth" {
  role   = aws_iam_role.cloudfront-auth.name
  policy = templatefile("${path.module}/policy/cloudfront-auth.json", { 
    account_id = data.aws_caller_identity.caller.account_id
  })
}

resource "aws_lambda_function" "cloudfront-auth" {
  depends_on    = [null_resource.cloudfront-auth]
  filename      = "${path.module}/app/dist/app.zip"
  function_name = var.function_name
  handler       = "index.handler"
  timeout       = 5
  role          = aws_iam_role.cloudfront-auth.arn

  runtime = "nodejs22.x"
  publish = true
}
