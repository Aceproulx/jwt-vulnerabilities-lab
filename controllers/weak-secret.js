const app = require('express')();
const jwt = require('jsonwebtoken');

/**
 * @swagger
 * /weak-secret:
 *   post:
 *     summary: Exploit Weak Secret vulnerability
 *     tags: [Weak Secret]
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
        // Validating JWT signature using weak secret
        const payload = jwt.verify(token, 'pirates');
        
        if(payload['admin']) {
            payload['flag'] = 'hakai{W34k_s3cr3t_4tt4ck}';
        }

        return res.json(payload);
    
    } catch(e) {
        return res.sendStatus(401);
    }
});

/**
 * @swagger
 * /weak-secret:
 *   get:
 *     summary: Return JWT token
 *     tags: [Weak Secret]
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
    const payload = {
        username: 'guest',
        admin: false
    };

    const token = jwt.sign(payload, 'pirates');

    return res.json({ token });
});

module.exports = app;