const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 5000;
const SECRET_KEY = process.env.SECRET_KEY || 'playboy'; // Use an environment variable for the secret key

app.use(bodyParser.json());

// Swagger setup
const swaggerOptions = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'CRUD API with JWT',
            version: '1.0.0',
            description: 'API documentation for CRUD operations with JWT authentication'
        },
        servers: [
            { url: `http://localhost:${PORT}` }
        ],
        components: {
            securitySchemes: {
                BearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        },
        security: [{
            BearerAuth: []
        }]
    },
    apis: [__filename]
};
const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Sample user data
const users = [
    {
        email: "andrei@gmail.com",
        password: bcrypt.hashSync('12345', 5),
        role: "ADMIN",
        permissions: ["WRITE", "READ"]
    },
    {
        email: "vasea@gmail.com",
        password: bcrypt.hashSync('12345', 5),
        role: "READER",
        permissions: ["READ"]
    }
];

/**
 * @swagger
 * components:
 *   schemas:
 *     Login:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *         password:
 *           type: string
 *     TokenResponse:
 *       type: object
 *       properties:
 *         token:
 *           type: string
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         message:
 *           type: string
 */

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login and receive a JWT
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Login'
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       401:
 *         description: Invalid email or password
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (email && password) {
        const user = users.find(u => u.email === email);
        if (user && bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign({ email: user.email, role: user.role, permissions: user.permissions }, SECRET_KEY, { expiresIn: '1m' });
            return res.status(200).json({ token });
        }
        return res.status(401).json({ message: 'Invalid email or password' });
    }
    return res.status(400).json({ message: 'Email and password are required' });
});

// Middleware to check JWT and permissions
const authenticateJWT = (permissionsRequired) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (authHeader) {
            const token = authHeader.split(' ')[1];
            jwt.verify(token, SECRET_KEY, (err, user) => {
                if (err) {
                    return res.sendStatus(403);
                }
                req.user = user;
                if (permissionsRequired.every(permission => user.permissions.includes(permission))) {
                    next();
                } else {
                    return res.sendStatus(403);
                }
            });
        } else {
            res.sendStatus(401);
        }
    };
};

/**
 * @swagger
 * /entities:
 *   get:
 *     summary: Get list of entities
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: skip
 *         schema:
 *           type: integer
 *         description: Number of entities to skip
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Number of entities to retrieve
 *     responses:
 *       200:
 *         description: List of entities
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   name:
 *                     type: string
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */
app.get('/entities', authenticateJWT(['READ']), (req, res) => {
    const { skip = 0, limit = 10 } = req.query;
    const entities = Array.from({ length: 100 }, (_, i) => ({ id: i, name: `Entity ${i}` }));
    const result = entities.slice(Number(skip), Number(skip) + Number(limit));
    res.status(200).json(result);
});

/**
 * @swagger
 * /entities:
 *   post:
 *     summary: Create a new entity
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *     responses:
 *       201:
 *         description: Entity created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 name:
 *                   type: string
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */
app.post('/entities', authenticateJWT(['WRITE']), (req, res) => {
    const { name } = req.body;
    if (name) {
        res.status(201).json({ id: Date.now(), name });
    } else {
        res.status(400).json({ message: 'Invalid input' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});