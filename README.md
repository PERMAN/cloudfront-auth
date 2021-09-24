# cloudfront-auth

Create an AWS Lambda@Edge that authenticates to Amazon ClouFront with OpenID Connect.

## USAGE

See [app/README.md](app/README.md) about variables.

```
module "cloudfront-auth" {
  source           = "github.com/PERMAN/cloudfront-auth"
  cloudfront_url   = ""
  client_id        = ""
  client_secret    = ""
  issuer           = ""
  authz_endpoint   = ""
  token_endpoint   = ""
  jwks_uri         = ""
  session_duration = ""
  encrypt_key      = ""
}

resource "aws_cloudfront_distribution" "example" {
  # ... other configuration ...

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = module.cloudfront-auth.cloudfront-auth_qualified_arn
      include_body = false
    }
}

```
