# cloudfront-auth

PERMAN Federationを利用して、Amazon CloudFront に OpenID Connectで認証をかけます。

## 事前準備

`.env`ファイルを作成してください。

```
# cloudfrontのドメイン
# https://example.com
CLOUDFRONT_URL=
# OpenID ConnectのクライアントID
CLIENT_ID=
# OpenID Connectのクライアントシークレット
CLIENT_SECRET=
# セッションの有効期限(秒)
SESSION_DURATION=
# Cookie暗号化用キー
# crypto.randomBytes(32).toString('hex')
ENCRYPT_KEY=
# デバッグモード
DEBUG=true or false
# 下記から設定を取得
# curl -k https://federation.perman.jp/.well-known/openid-configuration
ISSUER=
AUTHZ_ENDPOINT=
TOKEN_ENDPOINT=
JWKS_URI=
```

## インストール

```
npm install --production
```

