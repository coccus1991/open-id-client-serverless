const {Issuer} = require('openid-client');
const jwktopem = require("jwk-to-pem");
const jwt = require("jsonwebtoken");
const axios = require('axios');

// ENV VAR
let client_id = null;
let client_secret = null;
let domain = null;
let idp_metadata_url = null;

let idpIssuer = null;
let jwk = null;


async function discoverMetadata() {
    try {
        idpIssuer = await Issuer.discover(idp_metadata_url);
    } catch (e) {
        throw e;
    }

    try {
        const {data} = await axios.get(idpIssuer.metadata.jwks_uri);

        if (data.keys === undefined || !Array.isArray(data.keys))
            throw new Error("jwk invalid or missing")

        const sig = data.keys.find(e => e.use !== undefined && e.use === "sig")

        jwk = sig || data.keys[0];

    } catch (e) {
        throw e;
    }

}

function parseCookies(cookieHeader) {
    const list = {};
    if (!cookieHeader) return list;

    cookieHeader.split(`;`).forEach(function (cookie) {
        let [name, ...rest] = cookie.split(`=`);
        name = name?.trim();
        if (!name) return;
        const value = rest.join(`=`).trim();
        if (!value) return;
        list[name] = decodeURIComponent(value);
    });

    return list;
}

async function login(request) {
    const client = new idpIssuer.Client({
        client_id,
        client_secret,
        redirect_uris: [domain + "/cb"],
        response_types: ['code'],
    });

    const response = {
        status: '302',
        body: '',
        headers: {
            'location': [{
                key: 'Location',
                value: client.authorizationUrl()
            }]
        },
    };

    return response;
}

async function cb(request) {
    const client = new idpIssuer.Client({
        client_id,
        client_secret,
        redirect_uris: [domain + "/cb"],
        response_types: ['code'],
    });

    const params = client.callbackParams("?" + request.querystring.replace("?", ""));
    let tokenSet = null;

    if (params)
        try {
            tokenSet = await client.callback(domain + "/cb", params);

            return {
                status: '302',
                body: "",
                headers: {
                    'location': [{
                        key: 'Location',
                        value: "/"
                    }],
                    'set-cookie': [{
                        key: "Set-Cookie",
                        value: "authorization=" + tokenSet.access_token + "; HttpOnly"
                    }]
                },
            };
        } catch (e) {
        }

    return {
        status: '401',
        body: "Challenge not valid",
    }
}

async function check(request) {
    let token = null;

    if (request.headers.cookie !== undefined && Array.isArray(request.headers.cookie)) {
        const cookies = parseCookies(request.headers.cookie[0].value);

        if (typeof cookies["authorization"] !== undefined) {
            token = cookies["authorization"];
        }
    }

    if (!token)
        return {
            status: '302',
            body: "",
            headers: {
                'location': [{
                    key: 'Location',
                    value: "/login"
                }]
            },
        };

    try {
        jwt.verify(token, jwktopem(jwk));
    } catch (e) {
        return {
            status: '302',
            body: "",
            headers: {
                'location': [{
                    key: 'Location',
                    value: "/login"
                }]
            },
        }
    }

    return request;
}

async function api(request) {
    //rewrite rule for removing the prefix api in origin call
    request.uri = request.uri.replace(/^\/api/, "")

    if (request.headers.cookie !== undefined && Array.isArray(request.headers.cookie)) {
        const cookies = parseCookies(request.headers.cookie[0].value)


        if (typeof cookies["authorization"] !== undefined) {
            request.headers['authorization'] = [{
                "key": "Authorization",
                "value": "Bearer " + cookies["authorization"]
            }]
        }
    }

    return request;
}

module.exports.lambdaHandler = async (event, context, callback) => {
    const request = Object.assign({}, event.Records[0].cf.request);
    const split = request.uri.split("/");

    if (split.length > 1 && split[1] === "api")
        return callback(null, await api(request))

    if (!idpIssuer || jwk === null)
        try {
            client_id = request.origin.custom.customHeaders.client_id[0].value;
            client_secret = request.origin.custom.customHeaders.client_secret[0].value;
            domain = request.origin.custom.customHeaders.domain[0].value;
            idp_metadata_url = request.origin.custom.customHeaders.idp_metadata_url[0].value;
            await discoverMetadata();
        } catch (e) {
            return callback(null, {
                status: '500',
                body: "Error fetch metadata IDP",
            });
        }

    if (split.length > 1)
        switch (split[1]) {
            case "login":
                return callback(null, await login(request))
            case "cb":
                return callback(null, await cb(request))
        }

    return callback(null, await check(request))
}