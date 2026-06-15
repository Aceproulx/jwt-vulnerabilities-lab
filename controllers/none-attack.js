const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();

/**
 * @swagger
 * /none-attack:
 *   post:
 *     summary: Exploit None Attack vulnerability
 *     tags: [None Attack]
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
app.post("/", async (req,res) => {
    let secretKey;
    const token = req.headers['authorization'];

    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(header.alg.startsWith('HS')) {
            secretKey = "HS_S3cr3t_k3y";
        }

        if(header.alg.startsWith('RS')) {
            secretKey = fs.readFileSync(__dirname + '/../keys/public.pem', 'utf-8');
        }

        // Validating JWT signature using undefined secret and user-controlled algorithm.
        const payload = jwt.verify(token, secretKey, { algorithms: header.alg });

        if(payload['admin']) {
            payload['flag'] = 'hakai{N0n3_4tt4ck_1s_c00l}'
        }

        return res.json(payload);

    } catch(e) {
        return res.sendStatus(401);
    }
});

/**
 * @swagger
 * /none-attack:
 *   get:
 *     summary: Return JWT token
 *     tags: [None Attack]
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
app.get('/', async (req,res) => {
    const algorithms = ['HS256', 'RS256'];
    
    const keys = {
        'HS256': 'HS_S3cr3t_k3y',
        'RS256': fs.readFileSync(__dirname + '/../keys/private.pem', 'utf-8')
    };
    
    const payload = {
        username: 'guest',
        admin: false
    };

    const alg = algorithms[Math.floor(Math.random() * algorithms.length)]

    return res.json({ token: jwt.sign(payload, keys[alg], { algorithm: alg }) });
});

module.exports = app;
