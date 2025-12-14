const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'); // ❌ typo fixed
const path = require('path');
const usermodel = require('./models/user');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // ❌ was missing

// 👉 Set EJS as view engine
app.set('view engine', 'ejs');

// 👉 Set views folder
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
  res.render('register');
});
app.post('/register', async (req, res) => {
  let { email, password, username, name, age } = req.body;

  const user = await usermodel.findOne({ email }); // ✅ FIXED
  if (user) return res.status(409).redirect('/login');

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      let user = await usermodel.create({
        name,
        username,
        age,
        email,
        password: hash
      });

      let token = jwt.sign(
        { email: email, userid: user._id },
        'shhhh',
        { expiresIn: '1d' }
      );

      res.cookie('token', token);
      res.render('landingpage');
    });
  });
});
app.get('/login',(req,res)=>{
  res.render('login')
})
app.get('/landingpage',isLoggedIn,(req,res)=>{
  res.render('landingpage ')
})
// Port
app.post('/login', async (req, res) => {
    let { email, password } = req.body;

    const user = await usermodel.findOne({ email });
    if (!user) return res.redirect('/'); // redirect to register page listen we dont have anything in register route

    // compare password
    bcrypt.compare(password, user.password, (err, result) => {
        if (err) return res.status(500).send('Internal Server Error');

        if (result) {
            // password matched
            let token = jwt.sign({ email, userid: user._id }, 'shhhh', { expiresIn: '1d' });
            res.cookie('token', token, { httpOnly: true });
            return res.render('landingpage'); // ✅ redirect to a page after login
        } else {
            // password mismatch
            return res.redirect('/login');
        }
    });
});
app.get('/logout',(req,res)=>{
  res.cookie('token','')
  res.redirect("/login")
})

//here i am goint to create the middle ware:
function isLoggedIn(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).redirect('/login');
    }

    try {
        const data = jwt.verify(token, 'shhhh');
        req.user = data; // attach user info to request
        next(); // proceed to next middleware/route
    } catch (err) {
        return res.status(401).send('Invalid or expired token');
    }
}

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
