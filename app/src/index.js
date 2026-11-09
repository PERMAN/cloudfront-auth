const Cookie = require("cookie");
const Crypto = require("crypto");
const JsonWebToken = require("jsonwebtoken");
const JwkToPem = require("jwk-to-pem");
const QueryString = require("querystring");
const Axios = require("axios");
const Log = require("lambda-log");
const PkceChallenge = require("pkce-challenge");
var escapeHtml = require('escape-html')
require("dotenv").config();

exports.handler = async event => {
    Log.options.debug = process.env.DEBUG || false;
    try {
        const { request } = event.Records[0].cf;
        // Attach only the method and URI to every log entry (headers contain cookies, the query string contains the authorization code)
        Log.options.meta.request = { method: request.method, uri: request.uri };
        return await handleRequest(request);
    } catch (err) {
        Log.error(err);
        return generateInternalServerErrorResponse();
    }
};

async function handleRequest(request) {
    if (request.uri.startsWith("/_callback")) {
        return handleCallback(request);
    }
    if (!hasValidSession(request)) {
        return startAuthentication(request);
    }
    return request;
}

function hasValidSession(request) {
    try {
        const { headers } = request;
        const sub =
            "cookie" in headers && "CFA_SESSION" in Cookie.parse(headers.cookie[0].value)
                ? Cookie.parse(headers.cookie[0].value).CFA_SESSION
                : "";
        if (!sub) {
            return false;
        }
        const decryptedData = JSON.parse(decrypt(sub, "CFA_SESSION"));
        const now = getNow();
        if (!decryptedData) {
            return false;
        } else if (typeof decryptedData.sub !== "string" || decryptedData.sub === "") {
            return false;
        } else if (
            typeof decryptedData.expires_at !== "number" ||
            decryptedData.expires_at < now ||
            decryptedData.expires_at > now + parseInt(process.env.SESSION_DURATION) + CLOCK_SKEW_SECONDS
        ) {
            return false;
        }
        Log.debug(`authorized user: ${decryptedData.sub}`);
        return true;
    } catch (err) {
        Log.warn(err);
        return false;
    }
}

async function handleCallback(request) {
    const { headers, querystring } = request;
    const queryString = QueryString.parse(querystring);
    Log.debug(headers);
    Log.debug(queryString);
    if (queryString.error) {
        return generateUnauthorizedResponse(queryString.error);
    }
    if (!queryString.code) {
        return generateUnauthorizedResponse("no_code_found");
    }
    let oidcCtx;
    try {
        oidcCtx = JSON.parse(
            decrypt(Cookie.parse(headers.cookie[0].value).CFA_CTX, "CFA_CTX")
        );
    } catch (err) {
        Log.warn(err);
        return generateUnauthorizedResponse("time_out");
    }
    if (oidcCtx.expires_at < getNow()) {
        return generateUnauthorizedResponse("time_out");
    }
    if (queryString.state !== oidcCtx.state) {
        return generateUnauthorizedResponse("invalid_state");
    }
    const { idToken, decodedToken } = await getIdAndDecodedToken(
        queryString.code,
        oidcCtx.verifier
    );
    const jwks = await getJWKS();
    const rawPem = jwks.keys.filter(k => k.kid === decodedToken.header.kid)[0];
    if (rawPem === undefined) {
        throw new Error("unable to find expected pem in jwks keys");
    }
    const pem = JwkToPem(rawPem);
    try {
        await verifyJwt(idToken, pem, {
            algorithms: ["RS256"],
            audience: process.env.CLIENT_ID,
            issuer: process.env.ISSUER,
            nonce: oidcCtx.nonce
        });
        return generateAuthorizedResponse(decodedToken.payload.sub, oidcCtx.path);
    } catch (err) {
        Log.error(err);
        return generateUnauthorizedResponse();
    }
}

async function getIdAndDecodedToken(code, verifier) {
    const response = await Axios.post(
        process.env.TOKEN_ENDPOINT,
        QueryString.stringify({
            code: code,
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            redirect_uri: process.env.CLOUDFRONT_URL + "/_callback",
            grant_type: "authorization_code",
            code_verifier: verifier
        })
    );
    const decodedToken = JsonWebToken.decode(response.data.id_token, {
        complete: true
    });
    return { idToken: response.data.id_token, decodedToken };
}

function startAuthentication(request) {
    const nonce = Crypto.randomBytes(32).toString("hex");
    const state = Crypto.randomBytes(32).toString("hex");
    const pkce = PkceChallenge(128);
    return {
        status: "302",
        statusDescription: "Found",
        body: "Redirecting to OIDC provider",
        headers: {
            location: [
                {
                    key: "Location",
                    value: `${process.env.AUTHZ_ENDPOINT}?${QueryString.stringify({
                        client_id: process.env.CLIENT_ID,
                        redirect_uri: process.env.CLOUDFRONT_URL + "/_callback",
                        response_type: "code",
                        scope: "openid",
                        nonce: nonce,
                        state: state,
                        code_challenge: pkce.code_challenge,
                        code_challenge_method: "S256"
                    })}`
                }
            ],
            "set-cookie": [
                {
                    key: "Set-Cookie",
                    value: Cookie.serialize("CFA_SESSION", "", {
                        path: "/",
                        expires: new Date(1970, 1, 1, 0, 0, 0, 0)
                    })
                },
                {
                    key: "Set-Cookie",
                    value: Cookie.serialize(
                        "CFA_CTX",
                        `${encrypt(
                            JSON.stringify({
                                nonce: nonce,
                                state: state,
                                verifier: pkce.code_verifier,
                                path: request.uri.startsWith("/") ? request.uri : "/",
                                expires_at: getNow() + 180
                            }),
                            "CFA_CTX"
                        )}`,
                        {
                            path: "/",
                            httpOnly: true,
                            secure: true
                        }
                    )
                }
            ]
        }
    };
}

function generateAuthorizedResponse(sub, path) {
    const response = {
        status: "302",
        statusDescription: "Found",
        body: "ID token retrieved.",
        headers: {
            location: [
                {
                    key: "Location",
                    value: path.startsWith("/") ? path : "/"
                }
            ],
            "set-cookie": [
                {
                    key: "Set-Cookie",
                    value: Cookie.serialize(
                        "CFA_SESSION",
                        `${encrypt(
                            JSON.stringify({
                                sub: sub,
                                expires_at: getNow() + parseInt(process.env.SESSION_DURATION)
                            }),
                            "CFA_SESSION"
                        )}`,
                        {
                            path: "/",
                            maxAge: parseInt(process.env.SESSION_DURATION),
                            httpOnly: true,
                            secure: true
                        }
                    )
                },
                {
                    key: "Set-Cookie",
                    value: Cookie.serialize("CFA_CTX", "", {
                        path: "/",
                        expires: new Date(1970, 1, 1, 0, 0, 0, 0)
                    })
                }
            ]
        }
    };
    return response;
}

async function verifyJwt(token, pem, options) {
    return new Promise((resolve, reject) => {
        JsonWebToken.verify(token, pem, options, (err, decoded) => {
            if (err) {
                Log.error(err);
                return reject(err);
            }
            return resolve(decoded);
        });
    });
}

async function getJWKS() {
    return (await Axios.get(process.env.JWKS_URI)).data;
}

function getNow() {
    return Math.floor(Date.now() / 1000);
}

const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
// Tolerance for clock differences between Lambda@Edge instances when checking the expires_at upper bound
const CLOCK_SKEW_SECONDS = 60;

// AES-256-GCM. The cookie name is bound as AAD so that a value issued for one
// cookie (e.g. CFA_CTX) cannot be decrypted as another (e.g. CFA_SESSION).
// Output format: hex(iv || authTag || ciphertext)
function encrypt(data, cookieName) {
    const iv = Crypto.randomBytes(IV_LENGTH);
    const cipher = Crypto.createCipheriv(
        "aes-256-gcm",
        Buffer.from(process.env.ENCRYPT_KEY, "hex"),
        iv,
        { authTagLength: AUTH_TAG_LENGTH }
    );
    cipher.setAAD(Buffer.from(cookieName, "utf8"));
    const encryptedData = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encryptedData]).toString("hex");
}

function decrypt(encrypted, cookieName) {
    const buf = Buffer.from(encrypted, "hex");
    if (buf.length <= IV_LENGTH + AUTH_TAG_LENGTH) {
        throw new Error("invalid cookie value");
    }
    const decipher = Crypto.createDecipheriv(
        "aes-256-gcm",
        Buffer.from(process.env.ENCRYPT_KEY, "hex"),
        buf.subarray(0, IV_LENGTH),
        { authTagLength: AUTH_TAG_LENGTH }
    );
    decipher.setAAD(Buffer.from(cookieName, "utf8"));
    decipher.setAuthTag(buf.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH));
    const decryptedData = Buffer.concat([
        decipher.update(buf.subarray(IV_LENGTH + AUTH_TAG_LENGTH)),
        decipher.final()
    ]);
    return decryptedData.toString("utf8");
}

function generateUnauthorizedResponse(err) {
    const errors = {
        invalid_request: "Invalid Request",
        unsupported_response_type: "Unsupported Response Type",
        invalid_scope: "Invalid Scope",
        unauthorized_client: "Unauthorized Client",
        access_denied: "Access Denied",
        server_error: "Server Error",
        temporarily_unavailable: "Temporarily Unavailable",
        no_code_found: "No Code Found",
        invalid_state: "Invalid State",
        time_out: "Time Out"
    };

    let error = "User is Not Permitted";
    if(err && errors[err]) {
        error = errors[err];
    }

    const body = `<!DOCTYPE html>
    <html lang="en">
    <head>
        <!-- Simple HttpErrorPages | MIT License | https://github.com/AndiDittrich/HttpErrorPages -->
        <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>401 - Unauthorized</title>
        <style type="text/css">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,figure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{background-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline dotted}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic}mark{background-color:#ff0;color:#000}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:sans-serif;font-size:100%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset],[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focusring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:table;max-width:100%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{display:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:dotted 1px #707070}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fixed;width:100%;height:40px;left:0;bottom:0;color:#a0a0a0;font-size:14px}</style>
    </head>
    <body>
        <div class="cover"><h1>Unauthorized</h1><small>Error 401</small><p class="lead">${escapeHtml(error)}</p></div>
    </body>
    </html>
    `;

    return {
        body,
        status: "401",
        statusDescription: "Unauthorized",
        headers: {
            "set-cookie": [
                {
                    key: "Set-Cookie",
                    value: Cookie.serialize("CFA_SESSION", "", {
                        path: "/",
                        expires: new Date(1970, 1, 1, 0, 0, 0, 0)
                    })
                },
                {
                    key: "Set-Cookie",
                    value: Cookie.serialize("CFA_CTX", "", {
                        path: "/",
                        expires: new Date(1970, 1, 1, 0, 0, 0, 0)
                    })
                }
            ]
        }
    };
}

function generateInternalServerErrorResponse() {
    const body = `<!DOCTYPE html>
    <html lang="en">
    <head>
        <!-- Simple HttpErrorPages | MIT License | https://github.com/AndiDittrich/HttpErrorPages -->
        <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>500 - Internal Server Error</title>
        <style type="text/css">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,figure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{background-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline dotted}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic}mark{background-color:#ff0;color:#000}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:sans-serif;font-size:100%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset],[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focusring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:table;max-width:100%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{display:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:dotted 1px #707070}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fixed;width:100%;height:40px;left:0;bottom:0;color:#a0a0a0;font-size:14px}</style>
    </head>
    <body>
        <div class="cover"><h1>Internal Server Error <small>Error 500</small></h1></div>
    </body>
    </html>
    `;
    return { status: "500", statusDescription: "Internal Server Error", body };
}