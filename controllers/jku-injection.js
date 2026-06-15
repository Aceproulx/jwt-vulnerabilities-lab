const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const fs = require('fs');

/**
 * @swagger
 * /jku-injection:
 *   post:
 *     summary: Exploit JKU Header Injection vulnerability
 *     tags: [JKU Header Injection]
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *         description: Authorization token (JWT)
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *       401:
 *         content:
 *           application/json:
 *             schema:
 *               type: string
*/
app.post('/', async(req,res) => {
    const token = req.headers['authorization'];
    
    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(!header.jku) {
            return res.sendStatus(401);
        }

        // JKU Header without validation (JKU Header Injection vulnerability)
        const response = await fetch(header.jku);
        const jwks = await response.json();

        // Extracting RSA (public key) from JWK
        const publicKey = jwkToPem(jwks[0]);

        // Using public key to validate JWT signature
        const payload = jwt.verify(token, publicKey, { algorithms: 'RS256' });

        if(payload['admin']) {
            payload['flag'] = 'hakai{4bus3_jku_t0_sp00f_y0ur_publ1c_k3y}'
        }
        
        return res.json(payload);
        
    } catch(e) {
        return res.sendStatus(401);
    }
});

/**
 * @swagger
 * /jku-injection:
 *   get:
 *     summary: Return JWT token
 *     tags: [JKU Header Injection]
 *     responses:
 *       200:
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT
*/
app.get('/', async(req,res) => {
    const privateKey = fs.readFileSync(`${__dirname}/../keys/private.pem`, 'utf-8');

    const header = {
        jku: 'http://127.0.0.1:8000/jwks.json'
    };

    const payload = {
        username: 'guest',
        admin: false
    };

    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', header });

    return res.json({ token });
})

module.exports = app;