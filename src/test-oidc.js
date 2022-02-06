const { OAuth2Server } = require('oauth2-mock-server');

async function main() {
    let server = new OAuth2Server();

// Generate a new RSA key and add it to the keystore

// Start the server
    const jwk = await server.issuer.keys.generate('RS256');

    await server.start(8080, 'localhost');
    console.log('Issuer URL:', server.issuer.url); // -> http://localhost:8080

    const token = await server.issuer.buildToken();

    console.log(token)
// Do some work with the server
// ...

// Stop the server
    //await server.stop();
}

main();