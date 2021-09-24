# cloudfront-auth

## environment variables

```
# cloudfront url
CLOUDFRONT_URL=https://example.com

# cloudfront-auth session duration
SESSION_DURATION=86400
# cloudfront-auth cookie encrypt key
ENCRYPT_KEY= # crypto.randomBytes(32).toString('hex')
# enable debug mode. default false
DEBUG=true

# Please check with your OpenID Connect Provider
CLIENT_ID=
CLIENT_SECRET=
ISSUER=
AUTHZ_ENDPOINT=
TOKEN_ENDPOINT=
JWKS_URI=
```