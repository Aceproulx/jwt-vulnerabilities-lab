const express = require('express');
const jwt = require('jsonwebtoken');
const sequelize = require('../database/db');
const fs = require('fs');

const app = express();

/**
 * @swagger
 * /kid-injection/path-traversal:
 *   post:
 *     summary: Exploit KID Path traversal vulnerability
 *     tags: [KID Header Injection]
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
app.post('/path-traversal', async (req,res) => {
    let secretKey;
    const token = req.headers['authorization']
    
    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });
        
        // Path traversal on KID header
        secretKey = fs.readFileSync(`${__dirname}/../keys/${header.kid}`, 'utf-8');
        
        // Using file content like a secret key
        const payload = jwt.verify(token, secretKey, { algorithms: 'HS256' });

        if(payload['admin']) {
            payload['flag'] = 'hakai{k1d_h34d3r_p4th_tr4v3r54l}'
        }

        return res.json(payload);

    } catch(e) {
        return res.sendStatus(401);
    }
})

/**
 * @swagger
 * /kid-injection/sql-injection:
 *   post:
 *     summary: Exploit KID SQL Injection vulnerability
 *     tags: [KID Header Injection]
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
app.post('/sql-injection', async(req,res) => {
    const token = req.headers['authorization'];

    if(!token) {
        return res.sendStatus(401);
    }

    try {
        const { header } = jwt.decode(token, { complete: true });

        if(!header.kid) {
            return res.sendStatus(401);
        }
        
        // SQL Injection by KID Header content
        const [result,_] = await sequelize.query(`SELECT * FROM JwtKeys WHERE uuid = '${header.kid}'`);
        
        if(!result) {
            return res.sendStatus(401);
        }

        const key = result[0]['key'];

        // Using secret key retrieved from database
        const payload = jwt.verify(token, key, { algorithms: 'HS256' });

        if(payload['admin']) {
            payload['flag'] = 'hakai{sql_1nj3ct10n_k1d_h34d3r}'
        }

        return res.json(payload);
    
    } catch(e) {
        return res.sendStatus(401);
    }
})

/**
 * @swagger
 * /kid-injection:
 *   get:
 *     summary: Return JWT token
 *     tags: [KID Header Injection]
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
    const header = {
        kid: '698dc19d489c4e4db73e28a713eab07b'
    };
    
    const payload = {
        username: 'guest',
        admin: false,
    };

    const secretKey = fs.readFileSync(`${__dirname}/../keys/${header.kid}`, 'utf-8');

    const token = jwt.sign(payload, secretKey, { algorithm: 'HS256', header });

    return res.json({ token });
})


module.exports = app;