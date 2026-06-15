const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const fs = require('fs');

/**
 * @swagger
 * /algorithm-confusion:
 *   post:
 *     summary: Exploit Algorithm Confusion vulnerability
 *     tags: [Algorithm Confusion]
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

    const jku_whitelist = [
        'http://127.0.0.1:8000/jwks.json',
    ];

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(!header.jku || !jku_whitelist.includes(header.jku)) {
            return res.sendStatus(401);
        }

        const response = await fetch(header.jku);
        const jwks = await response.json();

        const publicKey = jwkToPem(jwks[0]);

        // The application expects the asymmetric algorithm, but the algorithm is controlled by the user.
        // Outdated "jsonwebtoken" vulnerability
        const payload = jwt.verify(token, publicKey, { algorithms: header.alg });
        
        if(payload['admin']) {
            payload['flag'] = 'hakai{alg0r1thm_c0nfus10n_111ssss_0p}'
        }

        return res.json(payload);
        
    } catch(e) {
        return res.sendStatus(401);
    }
});

/**
 * @swagger
 * /algorithm-confusion:
 *   get:
 *     summary: Return JWT token
 *     tags: [Algorithm Confusion]
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