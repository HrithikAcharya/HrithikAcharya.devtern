const mysql = require('mysql2');
const express = require('express');
const session = require('express-session');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const app = express();
let port = 8080;
const connection = mysql.createConnection({
    host     : 'localhost', //make changes accordingly
    user     : 'root', //make changes accordingly
    password : '@Hrithik014398', //make changes accordingly
    database : 'nodelogin' //make changes accordingly
});
connection.connect(error => {
    if (error) throw error;
    console.log("Successfully connected to the database.");
});

app.use(cookieParser());
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));
app.set("view engine", "ejs");
app.engine('ejs', require('ejs').renderFile);
app.set("views", path.join(__dirname, '/views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, ()=>{
    console.log(`listening at ${port}`);
});

// http://localhost:8080/
app.get('/', function(request, response) {
    // Render login template
    response.render("login");
});
app.get('/signup', function(request, response) {
    // Render signup template
    response.render("signup");
});
app.get('/forgotPassword', function(request, response) {
    // Render forgotPassword template
    response.render("forgotPassword");
});

// Handle login
app.post('/home', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const rememberMe = req.body.remember_me;

    if (username && password) {
        connection.query('SELECT * FROM accounts WHERE username = ?', [username], (error, results) => {
            if (error) throw error;
            console.log('Query Results:', results);
            if (results.length > 0) {
                req.session.loggedin = true;
                req.session.username = username;
                if (remember_me) {
                    res.cookie('username', username, { maxAge: 30 * 24 * 60 * 60 * 1000 });
                    res.cookie('password', password, { maxAge: 30 * 24 * 60 * 60 * 1000 });
                } else {
                    res.clearCookie('username');
                    res.clearCookie('password');
                }
                return res.redirect('/home');
            } else {
                return res.status(401).send('Incorrect Username and/or Password!');
            }
        });
    } 
	else {
		return res.status(401).send('Please enter Username and Password!');
	 }
	
});
app.get('/home', (req, res) => {
    console.log('Session:', req.session);
    console.log('Cookies:', req.cookies);

    if (req.session.loggedin || req.cookies.username) {
        let username = req.session.username || req.cookies.username;
        console.log('Logged in as:', username);
        res.render('home', { username });
    } else {
        res.send('<h1>Please login to view this page!</h1>');
    }
    res.end();
});

//Handle signup
 app.post('/signup', (req, res) => {
     let username = req.body.username;
     let email = req.body.email;
     let password = req.body.password;
     let confirm_password = req.body.confirm_password;

     console.log(`Username: ${username}, Email: ${email}, Password: ${password}, Confirm Password: ${confirm_password}`);

     if (password !== confirm_password) {
         return res.render('signup', { error: 'Passwords do not match.' });
     }
     connection.query('SELECT * FROM accounts WHERE email = ?', [email], (error, results) => {
         if (error) throw error;

         console.log('Check Existing Email Results:', results);

         if (results.length > 0) {
             return res.render('signup', { error: 'Email already in use.' });
         } else {
             connection.query('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)', [username, password, email], (err) => {
                 if (err) {
                     console.error('Error inserting user:', err);
                     return res.render('signup', { error: 'Error creating account.' });
                 }
                 console.log('User successfully created:', username);
                 res.redirect('/');
             });
         }
     });
 });
// Handle password reset
app.post('/forgotPassword', (req, res) => {
    let email = req.body.email;
    console.log(`Reset password for email: ${email}`);

    // Generate a new password (in a real application, you should generate a secure token and send an email)
    let newPassword = Math.random().toString(36).slice(-8); // generate a simple password
    console.log(`Generated new password: ${newPassword}`);

    connection.query('SELECT * FROM accounts WHERE email = ? ', [email], (error, results) => {
        if (error) throw error;

        if (results.length > 0) {
            connection.query('UPDATE accounts SET password = ? WHERE email = ?', [newPassword, email], (error, results) => {
                if (error) throw error;

                console.log(`Password reset successful for email: ${email}`);
                res.send(`Password reset successful. Your new password is: ${newPassword}`);
            });
        } else {
            console.log(`Password reset failed for email: ${email}`);
            res.send('Password reset failed. Please check your email and phone number and try again.');
        }
    });
});
// Encrypt function
function encrypt(text) {
    const iv = crypto.randomBytes(ivLength);
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(encryptionKey), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Decrypt function
function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(encryptionKey), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}
// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return res.redirect('/');
        }
        res.clearCookie('connect.sid'); // If using express-session
        res.redirect('/');
    });
});