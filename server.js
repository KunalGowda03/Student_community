const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const mariadb = require('mariadb');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const port = 8080;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads/';

        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    },
});

const upload = multer({ storage: storage });

const pool = mariadb.createPool({
    host: 'localhost',
    port: 3305,
    user: 'root',
    password: 'root',
    database: 'project1',
    connectionLimit: 5,
});

pool.getConnection()
    .then(connection => {
        console.log('Connected to the database');
        connection.release();
    })
    .catch(error => {
        console.error('Error connecting to the database:', error);
    });

app.use(express.json());

// User registration endpoint
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Username, password, and email are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await pool.getConnection();
        const insertQuery = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
        await connection.query(insertQuery, [username, hashedPassword, email]);
        connection.release();
        res.json({ message: 'User registered successfully.' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Error registering user.' });
    }
});

// User login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const connection = await pool.getConnection();
        const selectQuery = 'SELECT user_id, username, password FROM users WHERE username = ?';
        const result = await connection.query(selectQuery, [username]);
        connection.release();

        if (result.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        const user = result[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // You can generate and return a JWT token for authentication here
        res.json({ message: 'Login successful.', user_id: user.user_id });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Error logging in.' });
    }
});

// File upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    const fileName = req.file.originalname;
    const filePath = req.file.path;

    const connection = await pool.getConnection();

    try {
        const insertQuery = 'INSERT INTO files (filename, filepath) VALUES (?, ?)';
        await connection.query(insertQuery, [fileName, filePath]);
        res.json({ message: 'File uploaded successfully', fileName: fileName });
    } catch (insertError) {
        console.error('Error inserting file into database:', insertError);
        res.status(500).json({ error: 'Error uploading file.' });
    } finally {
        connection.release();
    }
});

// Get all files endpoint
app.get('/files', async (req, res) => {
    const connection = await pool.getConnection();

    try {
        const selectQuery = 'SELECT id, filename, filepath, description, uploaded_at FROM files';
        const results = await connection.query(selectQuery);
        res.json(results);
    } catch (selectError) {
        console.error('Error retrieving files from database:', selectError);
        res.status(500).json({ error: 'Error retrieving files.' });
    } finally {
        connection.release();
    }
});

app.use(express.static(__dirname));

server.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
