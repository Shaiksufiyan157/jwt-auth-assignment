const express=require("express")
const bcrypt=require("bcrypt")
const cookieParser = require('cookie-parser');const mongoose=require("mongoose")
const Person = require("./models/Person");
const app=express()
const jwt = require('jsonwebtoken');
require('dotenv').config();
app.use(express.urlencoded({ extended: true })); // to parse form data
app.use(express.static('public')); // serve static files (like CSS)
app.use(express.json());
app.use(cookieParser());

app.set('view engine','ejs')
app.get("/signup",(req,res)=>{
res.render("signup")
})

app.get("/login",(req,res)=>{
res.render("login")
})

//authentication middleware
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

mongoose.connect(process.env.MONGODB_STRING,);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
    console.log("Database connected");
});


// Signup Route
app.post('/signup', async (req, res) =>{
console.log(req.body)
const { username, email, password } = req.body;
  try {
    const existingUser = await Person.findOne({ email });
    if (existingUser) return res.send('Email already exists');

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new Person({ username:username, email: email, password: hashedPassword });
    await newUser.save();

    res.send('Signup successful!');
  }
    catch(err){
        console.log(err);
        res.status(500).json({error: 'Internal Server Error'});
    }
})

// Login Route
app.post('/login', async (req, res) => {
  const { email, password,username } = req.body;

  const user = await Person.findOne({ email });
  if (!user) return res.send('User not found');

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.send('Invalid password');

  const token = jwt.sign({ email:email }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.cookie('token', token, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  });

  res.send(`Signed in! Welcome back, ${user.username}`);
});
app.get('/dashboard', authenticateToken, (req, res) => {
  res.render('dashboard');
});
app.get('/logout', (req, res) => {
  res.clearCookie('token'); // clears cookie named 'token'
  res.send('Logged out successfully');
});
const PORT =3000

app.listen(PORT,()=>{
console.log(`server is running on ${PORT}`)
})
