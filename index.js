
require('dotenv').config();
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const cors = require('cors');
const app = express();
const port = 7654;

const { User } = require('./models');

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const allowedOrigins = ['http://103.163.111.39:3000','https://paud-client.vercel.app'];
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb' }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, email: user.email }, ACCESS_TOKEN_SECRET, { expiresIn: '10s' });
}

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, email: user.email }, REFRESH_TOKEN_SECRET, { expiresIn: '1d' });
}

app.get('/', (req, res) => {
  res.send('Hello world!');
})

app.get('/users', async (req, res) => {
  const users = await User.findAll();
  res.json(users);
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({
    where: {
      username: username
    }
  });
  if (!user) return res.status(400).json({ msg: 'Akun tidak ditemukan' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ msg: 'Password salah' });
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  await User.update({ refresh_token: refreshToken }, {
    where: {
      id: user.id
    }
  })
  res.json({ accessToken, refreshToken });
});

app.get('/set-cookie', (req, res) => {
  return res.json({ status: 200, token: 'lerian' });
});

app.post('/protected', (req, res) => {
  jwt.verify(req.body.token, ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log('unauthorized')
      return res.json({ message: 'Unauthorized' });
    } else {
      console.log('access grandted')
      return res.json({ message: 'Access granted' });
    }
  });
});

app.post('/refresh', async (req, res) => {
  const refreshToken = req.body.token;
  const user = await User.findOne({
    where: {
      refresh_token: refreshToken
    }
  });
  if (!refreshToken || !user) {
    return res.json({ status: 'tidak oke' })
  } 

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.json({ status: 'tidak oke' })
    }
    const accessToken = jwt.sign({ id: user.id, username: user.username }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
  });
});

app.post('/logout', async (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.status(204).json({ status: 'tidak oke' });
  const user = await User.findOne({
    where: {
      refresh_token: refreshToken
    }
  });
  if (!user) return res.status(204).json({ status: 'tidak oke' });
  const userId = user.id
  await User.update({
    refresh_token: null
  }, {
    where: {
      id: userId
    }
  });
  return res.status(200).json({ status: 'oke' });
})

app.listen(port, () => {
  console.log(`http://localhost:${port}`);
})