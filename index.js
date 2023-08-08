
require('dotenv').config();
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const app = express();
const port = 5000;

const verifyToken = require('./middleware/verifyToken');
const { User } = require('./models');

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb' }));
app.use(cookieParser());

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, email: user.email }, ACCESS_TOKEN_SECRET, { expiresIn: '50s' });
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
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ accessToken });
})

app.get('/protected', verifyToken, (req, res) => {
  res.send('oke');
});

app.get('/token', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    const user = await User.findOne({
      where: {
        refresh_token: refreshToken
      }
    });
    if (!user) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) return res.sendStatus(403);
      const accessToken = jwt.sign({ id: user.id, username: user.username, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '50s' });
      res.json({ accessToken });
    });
  } catch (error) {
    res.send(error)
  }
})

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
  },{
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