require('dotenv').config()
const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const cors = require('cors')

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const server = express()
server.use(express.json())
server.use(cors())

const dbPath = process.env.DBPATH
    ? path.resolve(process.env.DBPATH)  // Convert relative to absolute path
    : path.join(__dirname, 'expenseflow.db');
const BASE_URL = process.env.BASE_URL || 'http://localhost:8080'
const PORT = process.env.PORT || 8080
const SECRET_KEY = process.env.JWT_SECRET_KEY || 'awsedrftgyhujikolpqzmxncbv1470963258';

let db;

const initializeServer = async () => {
    try{
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        })
        await db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                email TEXT UNIQUE,
                password TEXT
            );
        `);
        await db.run(`
            CREATE TABLE IF NOT EXISTS expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                amount FLOAT,
                category TEXT,
                payment_method TEXT,
                date DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        `);
        // res.send('Hello User, Welcome to ExpenseFlow Server.')
        server.listen(PORT, () => console.log(`Server running at ${BASE_URL}`))
    } catch(e) {
        console.log('SERVER STOPPED')
        console.error('ERROR: ', e.message)
        process.exit(1)
    }
}

initializeServer()

server.get('/', async(req, res) => {
    res.send('Hello User, Welcome to ExpenseFlow Server.')
})

// User Registration
server.post('/signup', async(req,res) => {
    const {username, email, password} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        await db.run(`
            INSERT INTO users (username, email, password)
            VALUES (?,?,?)
            `,[username,email,hashedPassword]);
        res.status(201).send('User Registered Successfully');
    } catch (e) {
        res.status(400).send('User Account already exists');
    }
})

// User Login
server.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userDetails = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
        if (!userDetails) {
            return res.status(401).json({ error: 'User Account Not Exists.' });
        }
        const checkPassword = await bcrypt.compare(password, userDetails.password);
        if (!checkPassword) {
            return res.status(401).json({ error: 'Incorrect Password, Try Again' });
        }
        const token = jwt.sign({ userId: userDetails.id }, SECRET_KEY, { expiresIn: '3h', algorithm: 'HS256' });
        return res.json({ username: userDetails.username, jwt_token: token });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Authentication MiddleWare
const authTokenMiddleware = (req,res,next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).send('Access Denied: No Token Provided');
    }
    const token = authHeader.split(' ')[1]; // Extracting token
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).send('Invalid Token');
        req.user = user;
        next();
    });
}

// Add Expense
server.post('/expenses', authTokenMiddleware, async(req,res) => {
    const {title, amount, category, payment_method, date} = req.body 
    await db.run(`
        INSERT INTO expenses (user_id,title,amount,category,payment_method, date)
            VALUES (?,?,?,?,?,?)
        `,[req.user.userId,title,amount,category,payment_method,date]);
    res.status(201).send('Added Expense')
})

// Get User Expenses
server.get('/expenses', authTokenMiddleware, async(req,res)=> {
    const getAllExpenses = await db.all(`
        SELECT * FROM expenses
            WHERE user_id = ?
        `,[req.user.userId]);
    res.json(getAllExpenses);
})

// Update expenses table from id
server.put('/expenses/:id', authTokenMiddleware, async (req, res) => {
    const { id } = req.params;
    const { title, amount, category, payment_method, date } = req.body;

    const expense = await db.get(`
            SELECT * FROM expenses WHERE id = ? AND user_id = ?
        `, [id, req.user.userId]);

    if (!expense) return res.status(404).send('Expense Not Found');

    try {
        await db.run(`
            UPDATE expenses 
            SET title = ?, amount = ?, category = ?, payment_method = ?, date = ?
            WHERE id = ? AND user_id = ?`,
            [title, amount, category, payment_method, date, id, req.user.userId]
        );
        res.send('Expense Updated Successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error updating expense');
    }
});


// DELETE User Expense
server.delete('/expenses/:id', authTokenMiddleware, async(req,res)=> {
    const {id} = req.params;
    const resultedData = await db.run(`
        DELETE FROM expenses
            WHERE id = ? AND user_id = ?
        `,[id, req.user.userId]);
    if (resultedData.changes === 0) return res.status(404).send('Expense Not Found');
    res.send('Expense Deleted.');
})

module.exports = server;