# cloudfront-auth

Create an AWS Lambda@Edge that authenticates to Amazon CloudFront with OpenID Connect.

## USAGE

See [app/README.md](app/README.md) about variables.

```
module "cloudfront-auth" {
  source           = "github.com/PERMAN/cloudfront-auth"
  function_name    = "" # default "cloudfront-auth"
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

### Example

If the OpenID Provider is Google.

```
module "cloudfront-auth" {
  source           = "github.com/PERMAN/cloudfront-auth"
  cloudfront_url   = "https://www.example.com"
  client_id        = "id"
  client_secret    = "secret"
  issuer           = "https://accounts.google.com"
  authz_endpoint   = "https://accounts.google.com/o/oauth2/v2/auth"
  token_endpoint   = "https://oauth2.googleapis.com/token"
  jwks_uri         = "https://www.googleapis.com/oauth2/v3/certs"
  session_duration = "86400"
  encrypt_key      = "encryption key"
  function_name    = "example-cloudfront-auth"
}
```


## Redirect URI

The `redirect_uri` to be set for OpenID Provider should be set as follows.

```
https://{cloudfront_url}/_callback
```
