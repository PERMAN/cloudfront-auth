#!/bin/bash
cd app/
npm install
npm run build
echo -n > .env
echo CLOUDFRONT_URL=$CLOUDFRONT_URL >> .env
echo CLIENT_ID=$CLIENT_ID >> .env
echo CLIENT_SECRET=$CLIENT_SECRET >> .env
echo ISSUER=$ISSUER >> .env
echo AUTHZ_ENDPOINT=$AUTHZ_ENDPOINT >> .env
echo TOKEN_ENDPOINT=$TOKEN_ENDPOINT >> .env
echo JWKS_URI=$JWKS_URI >> .env
echo SESSION_DURATION=$SESSION_DURATION >> .env
echo ENCRYPT_KEY=$ENCRYPT_KEY >> .env
mv .env dist/
cd dist && zip -9 -r app.zip .