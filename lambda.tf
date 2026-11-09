locals {
  # Hash of the build inputs (source files and the values written to .env by build.sh).
  # Changing any of these rebuilds the package and updates the Lambda function.
  app_source_hash = sha256(join("", concat(
    [
      for f in concat(
        ["build.sh", "app/package.json", "app/package-lock.json", "app/rollup.config.js", "app/.npmrc"],
        [for s in sort(fileset("${path.module}/app/src", "**")) : "app/src/${s}"]
      ) : filesha256("${path.module}/${f}")
    ],
    [nonsensitive(sha256(jsonencode({
      cloudfront_url   = var.cloudfront_url
      client_id        = var.client_id
      client_secret    = var.client_secret
      issuer           = var.issuer
      authz_endpoint   = var.authz_endpoint
      token_endpoint   = var.token_endpoint
      jwks_uri         = var.jwks_uri
      session_duration = var.session_duration
      encrypt_key      = var.encrypt_key
    })))]
  )))
}

resource "null_resource" "cloudfront-auth" {
  triggers = {
    app_source_hash = local.app_source_hash
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
  depends_on       = [null_resource.cloudfront-auth]
  filename         = "${path.module}/app/dist/app.zip"
  source_code_hash = local.app_source_hash
  function_name    = var.function_name
  handler          = "index.handler"
  timeout          = 5
  role             = aws_iam_role.cloudfront-auth.arn

  runtime = "nodejs22.x"
  publish = true
}
