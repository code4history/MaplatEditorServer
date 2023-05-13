import { Hono } from "hono";
import { RegExpRouter } from "hono/router/reg-exp-router";
import {SignJWT, jwtVerify} from "jose";
import { cors } from 'hono/cors';

export const app = new Hono({ router: new RegExpRouter() });

app.use(
    '/users',
    cors({
        origin: '*',
        allowHeaders: ['*'],
        allowMethods: ['POST', 'GET', 'OPTIONS']
    })
)

app.get("/users", async (c) => {
    let token;
    let keyPair;
    let strPublicKey;
    try {
        keyPair = await crypto.subtle.generateKey(
            {
                name: "RSA-PSS",
                modulusLength: 2048, //can be 1024, 2048, or 4096
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
            },
            true,
            ["sign", "verify"]
        );

        let exported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        let exportedAsString = ab2str(exported);
        let exportedAsBase64 = btoa(exportedAsString);
        strPublicKey = `-----BEGIN PUBLIC KEY-----${exportedAsBase64}-----END PUBLIC KEY-----`;

        token = await new SignJWT({ "urn:example:claim": true })
            .setProtectedHeader({ alg: "PS256" })
            // .setProtectedHeader({ alg: "PS512" })
            .setIssuedAt()
            .setIssuer("urn:example:issuer")
            .setAudience("urn:example:audience")
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);
        const { payload, protectedHeader } = await jwtVerify(
            token,
            keyPair.publicKey,
            {
                issuer: "urn:example:issuer",
                audience: "urn:example:audience",
            }
        );

        console.log(`OK > ${JSON.stringify({
            token,
            payload,
            protectedHeader,
            publicKey: strPublicKey,
        })}`);
        return c.json({
            token,
            payload,
            protectedHeader,
            publicKey: strPublicKey,
        });
    } catch (e) {
        console.log(`error > ${JSON.stringify(e)}`);
        return c.html(JSON.stringify(e));
    }
});

/*app.all('*', async (c) => {
    const origin = c.req.headers.get('Origin')
    // You can validate origin here.
    console.log('origin > ', origin)
    if (c.req.method === 'OPTIONS') {
        // Make sure the necesssary headers are present for this to be a
        // valid pre-flight request
        if (
            c.req.headers.get('Origin') !== null &&
            c.req.headers.get('Access-Control-Request-Method') !== null &&
            c.req.headers.get('Access-Control-Request-Headers') !== null
        ) {
            // Handle CORS pre-flight request.
            // If you want to check the requested method + headers
            // you can do that here.
            console.log('pre-flight')
            c.header('Access-Control-Allow-Origin', origin)
            c.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS')
            c.header('Access-Control-Allow-Headers', '*')
            return c.text(null)
        } else {
            // Handle standard OPTIONS request.
            console.log('Standard OPTIONS')
            c.header('Allow', 'GET, HEAD, OPTIONS')
            return c.text(null)
        }
    } else {
        c.status(404)
        return c.text('404, not found!')
    }
})*/

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

export default app;