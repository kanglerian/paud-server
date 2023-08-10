
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

// const verifyToken = require('./middleware/verifyToken');
const { User } = require('./models');

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    // Allow requests from specific origins
    const allowedOrigins = ['https://paud-client.vercel.app','https://api.politekniklp3i-tasikmalaya.ac.id'];
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
  res.cookie('refreshToken', refreshToken, {
    maxAge: 3600000, // 1 hour
    httpOnly: true, // Cookie can't be accessed by JavaScript
    secure: true, // Send only over HTTPS
    sameSite: 'none', // Allow cross-site requests
  });
  res.json({ accessToken, refreshToken });
});

app.get('/set-cookie', (req, res) => {
  res.cookie('username', 'endang', {
    maxAge: 3600000, // 1 hour
    httpOnly: true, // Cookie can't be accessed by JavaScript
    secure: true, // Send only over HTTPS
    sameSite: 'none', // Allow cross-site requests
  });
  res.send('Cookie set successfully');
});

app.get('/get-cookie', (req, res) => {
  const username = req.cookies.username;
  if (username) {
    res.send(`Nilai cookie username: ${username}`);
  } else {
    res.send('Cookie username tidak ditemukan');
  }
});

app.get('/protected', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    res.json({ message: 'Access granted', user: decoded });
  });
});

app.post('/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  const user = await User.findOne({
    where: {
      refresh_token: refreshToken
    }
  });
  if (!refreshToken || !user) {
    return res.sendStatus(401);
  }

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    const accessToken = jwt.sign({ id: user.id, username: user.username }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
  });
});

app.delete('/logout', async (req, res) => {

  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.sendStatus(204);
  const user = await User.findOne({
    where: {
      refresh_token: refreshToken
    }
  });
  if (!user) return res.sendStatus(204);
  const userId = user.id
  await User.update({
    refresh_token: null
  }, {
    where: {
      id: userId
    }
  });
  res.clearCookie('refreshToken');
  return res.sendStatus(200);
})

app.listen(port, () => {
  console.log(`http://localhost:${port}`);
})