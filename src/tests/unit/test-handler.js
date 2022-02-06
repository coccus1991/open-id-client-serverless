'use strict';

const app = require('../../app.js');
const chai = require('chai');
const expect = chai.expect;

const loginEvent = require("../events/login.json");
const callbackEvent = require("../events/callback.json");
const checkEvent = require("../events/check.json");
const apiEvent = require("../events/api.json");

const {OAuth2Server} = require('oauth2-mock-server');

const client_id = process.env.CLIENT_ID;
const client_secret = process.env.CLIENT_SECRET;
const domain = process.env.DOMAIN;
const idp_metadata_url = process.env.IDP_METADATA_URL;

const customHeaders = {
    "client_id": [
        {
            "key": "CLIENT_ID",
            "value": client_id
        }
    ],
    "client_secret": [
        {
            "key": "CLIENT_SECRET",
            "value": client_secret
        }
    ],
    "domain": [
        {
            "key": "DOMAIN",
            "value": domain
        }
    ],
    "idp_metadata_url": [
        {
            "key": "IDP_METADATA_URL",
            "value": idp_metadata_url
        }
    ]
};

loginEvent.Records[0].cf.request.origin.custom.customHeaders = customHeaders;
callbackEvent.Records[0].cf.request.origin.custom.customHeaders = customHeaders;
checkEvent.Records[0].cf.request.origin.custom.customHeaders = customHeaders;

const server = new OAuth2Server();

describe('Login auth code flow', function () {
    let serverPort = 8080;

    before(async function () {
        await server.issuer.keys.generate('RS256');
        await server.start(serverPort, 'localhost');
    })

    it('It should redirect to IDP login page', async () => {
        await app.lambdaHandler(loginEvent, null, function (a, response) {
            const expected = {
                "status": "302",
                "body": "",
                "headers": {
                    "location": [{
                        "key": "Location",
                        "value": `http://localhost:${serverPort}/authorize?client_id=${process.env.CLIENT_ID}&scope=openid&response_type=code&redirect_uri=${encodeURIComponent(process.env.DOMAIN + '/cb')}`
                    }]
                }
            };

            expect(response).to.be.deep.equal(expected)
        });
    });

    it('It should after to have completed the code flow with the IDP provider, set a cookie named "authorization" with the "access_token"', async () => {
        await app.lambdaHandler(callbackEvent, null, function (a, response) {
            expect(response).to.contain({
                status: "302"
            });

            expect(response).to.have.nested.property("headers.set-cookie")

            const access_token = response.headers["set-cookie"][0].value.split(";")[0].replace(/^authorization\=/, "")

            expect(access_token).not.be.empty.and.not.be.undefined.and.not.be.null
        });
    });

    it('it should have success checking a valid authorization token', async () => {
        const token = await server.issuer.buildToken();

        checkEvent.Records[0].cf.request.headers.cookie = [
            {
                "key": "Cookie",
                "value": `authorization=${token}`
            }
        ];

        await app.lambdaHandler(checkEvent, null, function (a, response) {
            expect(response).to.be.deep.equal(checkEvent.Records[0].cf.request)
        })
    });

    it('It should fail the check for invalid authorization token', async () => {
        checkEvent.Records[0].cf.request.headers.cookie = [
            {
                "key": "Cookie",
                "value": `authorization=eyJraWQiOiJjYmNlNTRiNTZiMDU5NDY0MjEyNzNkZjQyYzM5NzM0Y2E3YTJiNTI3NWI0ZmIxNzZiZWU1NmI4YmI5YzE0NGM0ZGU0OTliOTFlY2UwZmI4ZSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpYXQiOjE2NDM2MzgwNzAsImV4cCI6MTY0MzY0MTY3MCwibmJmIjoxNjQzNjM4MDYwfQ.tShRRSDkN5Tm4543lm6PEwNyex5uTTLKOEYOGNYn-k7IoZpAVvnlFoh2JnVJ8ooxo9ucXJo19LOchPvBVWOVtb05haK2_C6UW36xvBFoLf1j4tPz_hkxrPiPK0KoA8p-P0tJuldhXRZNaDR7RPuQ3p8qDjXS3tI6Ht9YmNnLOGTVwm73Pu04tLw65ZVj9CxDU3ynIUr8akqRUlkZHw3MW90YiSJl8n7CClmPLweqCW0IcMDiVdqnRe3ANcQWhhAPG1axqB_R7st_wD1dwZqWPuI3q1tzUbyAO28GQuHro0-0keD4RE50MS4S9VQL9e-VHcX461mBqBCMnWS42zF7HA`
            }
        ];

        await app.lambdaHandler(checkEvent, null, function (a, response) {
            expect(response).to.be.deep.equal({
                status: '302',
                body: "",
                headers: {
                    'location': [{
                        key: 'Location',
                        value: "/login"
                    }]
                },
            });
        })
    });

    after(async function () {
        await server.stop();
    });
});

describe('Test api endpoint', function () {
    it('It should remove the prefix path "api" from the uri parameter', async function () {
        await app.lambdaHandler(apiEvent, null, function (a, response) {
            expect(response).to.have.property("uri", "/route")
        })
    });

    it('It should take the "access_token" from the cookie named "authorization" and inject in the response header as Authorization Bearer header', async function () {
        const expected = "Bearer dsfsd45xds";

        await app.lambdaHandler(apiEvent, null, function (a, response) {
            expect(response).to.have.nested.property("headers.authorization[0].value", expected)
        })
    });
})