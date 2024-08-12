require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 8000;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false // Ensure SSL connection
    }
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// User Registration
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Error hashing password');

        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
            if (err) return res.status(500).send('Error registering user');
            res.status(201).send('User registered successfully');
        });
    });
});

// User Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || results.length === 0) return res.status(401).send('User not found');

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) return res.status(401).send('Invalid password');

            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ token });
        });
    });
});

// Middleware to Verify Token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];  // Extract token after 'Bearer '
    if (!token) return res.status(403).send('No token provided');

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('JWT verification error:', err);
            return res.status(500).send('Failed to authenticate token');
        }
        req.userId = decoded.id;
        next();
    });
};


// Protect Flashcard Routes
app.use('/api/flashcards', verifyToken);

// Fetch all flashcards for the authenticated user

app.get('/api/flashcards', (req, res) => {
    db.query('SELECT * FROM flashcards WHERE user_id = ?', [req.userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching flashcards');
        res.json(results);
    });
});


// Add a new flashcard
app.post('/api/flashcards', (req, res) => {
    const { question, answer } = req.body;
    db.query('INSERT INTO flashcards (question, answer, user_id) VALUES (?, ?, ?)', [question, answer, req.userId], (err, results) => {
        if (err) return res.status(500).send(err);
        res.status(201).send('Flashcard added successfully');
    });
});


// Update a flashcard
app.put('/api/flashcards/:id', (req, res) => {
    const { id } = req.params;
    const { question, answer } = req.body;

    db.query('UPDATE flashcards SET question = ?, answer = ? WHERE id = ? AND user_id = ?', 
             [question, answer, id, req.userId], 
             (err, results) => {
        if (err) return res.status(500).send('Error updating flashcard');
        if (results.affectedRows === 0) return res.status(404).send('Flashcard not found or you do not have permission to edit this flashcard');
        res.send('Flashcard updated successfully');
    });
});


// Delete a flashcard
app.delete('/api/flashcards/:id', (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM flashcards WHERE id = ? AND user_id = ?', 
             [id, req.userId], 
             (err, results) => {
        if (err) return res.status(500).send('Error deleting flashcard');
        if (results.affectedRows === 0) return res.status(404).send('Flashcard not found or you do not have permission to delete this flashcard');
        res.send('Flashcard deleted successfully');
    });
});




app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
