# JWT Authentication with Cookie-Based Sessions in Express.js

This project implements secure user authentication in an Express.js app using JSON Web Tokens (JWT) and HTTP-only cookies. It features a simple signup/login system, stores the JWT in a cookie, and protects routes using a middleware.

🔧 Tech Stack

Node.js & Express.js
MongoDB + Mongoose
JWT (jsonwebtoken)
bcrypt (for password hashing)
cookie-parser
dotenv (for secure env variable handling)
EJS (for rendering templates)

---

📁 Project Structure

├── models/
│ └── Person.js # Mongoose user schema
├── views/
│ ├── signup.ejs # Signup page
│ ├── login.ejs # Login page
│ └── dashboard.ejs # Protected dashboard
├── .env # Environment variables
├── index.js # Main Express application
├── package.json




---

📝 .env File

Create a `.env` file in the root directory to securely store configuration:

env
MONGODB_STRING=mongodb://localhost:27017/auth-app1
JWT_SECRET=12345@ABC
How to Run the Project
Install dependencies


npm install
Start MongoDB locally, or update the URI in .env for Atlas or remote DB.

Run the server


node index.js
The server starts at http://localhost:3000.

🔐 Authentication Flow
1. User Signup
Route: POST /signup

Stores username, email, and hashed password using bcrypt.

Checks if the user already exists based on email.

2. User Login
Route: POST /login

Validates credentials.

Generates a JWT using jsonwebtoken.

Stores the token in an HTTP-only cookie:


res.cookie('token', token, {
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000 // 1 day
});


3. Protected Routes
Middleware checks the token in req.cookies.token:


function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('Access Denied: No Token');
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
}
Route: GET /dashboard uses the middleware to allow access only to authenticated users.

4. Logout
Route: GET /logout

Clears the token cookie:


res.clearCookie('token');
res.send('Logged out successfully');


📄 Sample Routes
Route	Method	Description
/signup	GET	Signup form
/signup	POST	Handle new user signup
/login	GET	Login form
/login	POST	Authenticate user
/dashboard	GET	Protected dashboard
/logout	GET	Logout and clear token

✅ Security Notes
JWT is stored in a httpOnly cookie, protecting it from XSS.

Passwords are securely hashed using bcrypt.

All environment secrets are stored in .env.

📦 Dependencies
See package.json for full list:

express, mongoose, jsonwebtoken, bcrypt, cookie-parser, dotenv, ejs

