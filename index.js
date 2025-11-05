const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

const TMDB_KEY = process.env.TMDB_KEY || '';
const TMDB_API = 'https://api.themoviedb.org/3';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

const db = new sqlite3.Database('./data.db');

// Passport Google strategy (only active if envs provided)
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback'
  }, function(accessToken, refreshToken, profile, done) {
    return done(null, profile);
  }));
}

function authMiddleware(req, res, next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({error:'No auth'});
  const token = h.replace('Bearer ','');
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (e) {
    return res.status(401).json({error:'Invalid token'});
  }
}

// TMDb proxy: simple search and discover/popular
app.get('/api/search', async (req, res) => {
  const q = req.query.q || '';
  const page = req.query.page || 1;
  try {
    const url = q ? `${TMDB_API}/search/movie?api_key=${TMDB_KEY}&language=en-US&query=${encodeURIComponent(q)}&page=${page}&include_adult=false`
                  : `${TMDB_API}/movie/popular?api_key=${TMDB_KEY}&language=en-US&page=${page}`;
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/movie/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const url = `${TMDB_API}/movie/${id}?api_key=${TMDB_KEY}&language=en-US&append_to_response=videos,credits,recommendations`;
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Auth (email/password)
app.post('/api/auth/register', body('email').isEmail(), body('password').isLength({min:6}), async (req, res) => {
  const errors = validationResult(req);
  if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()});
  const { email, password, name } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (email, password_hash, name) VALUES (?,?,?)`, [email, hash, name||null], function(err){
    if(err){
      console.error(err);
      return res.status(400).json({error:'Email mungkin sudah terdaftar'});
    }
    const user = { id: this.lastID, email, name, role: 'user' };
    const token = jwt.sign(user, JWT_SECRET, {expiresIn:'7d'});
    res.json({ user, token });
  });
});

app.post('/api/auth/login', body('email').isEmail(), async (req,res)=>{
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
    if(err) { console.error(err); return res.status(500).json({error:'Server error'}); }
    if(!row) return res.status(400).json({error:'Email not found'});
    const ok = await bcrypt.compare(password, row.password_hash || '');
    if(!ok) return res.status(400).json({error:'Password salah'});
    const user = { id: row.id, email: row.email, name: row.name, role: row.role };
    const token = jwt.sign(user, JWT_SECRET, {expiresIn:'7d'});
    res.json({ user, token });
  });
});

app.get('/api/me', authMiddleware, (req,res)=>{
  db.get(`SELECT id,email,name,role FROM users WHERE id = ?`, [req.user.id], (err,row)=>{
    if(err) return res.status(500).json({error:'Server error'});
    res.json({ user: row });
  });
});

// Watchlist
app.post('/api/watchlist', authMiddleware, body('movie_id').isInt(), (req,res)=>{
  const userId = req.user.id;
  const movieId = req.body.movie_id;
  db.run(`INSERT OR IGNORE INTO watchlists (user_id, movie_id) VALUES (?,?)`, [userId, movieId], function(err){
    if(err) { console.error(err); return res.status(500).json({error:'Server error'}); }
    res.json({ ok:true });
  });
});
app.get('/api/watchlist', authMiddleware, (req,res)=>{
  const userId = req.user.id;
  db.all(`SELECT movie_id, added_at FROM watchlists WHERE user_id = ?`, [userId], (err, rows) => {
    if(err) return res.status(500).json({error:'Server error'});
    res.json({ items: rows });
  });
});

// Comments
app.post('/api/comments', authMiddleware, body('movie_id').isInt(), body('text').isLength({min:1}), (req,res)=>{
  const userId = req.user.id;
  const { movie_id, text } = req.body;
  db.run(`INSERT INTO comments (user_id, movie_id, text) VALUES (?,?,?)`, [userId, movie_id, text], function(err){
    if(err) return res.status(500).json({error:'Server error'});
    res.json({ ok:true, id: this.lastID });
  });
});
app.get('/api/comments/:movieId', (req,res)=>{
  const movieId = req.params.movieId;
  db.all(`SELECT c.id, c.text, c.created_at, c.is_hidden, u.id as user_id, u.name as user_name FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.movie_id = ? ORDER BY c.created_at DESC`, [movieId], (err, rows)=>{
    if(err) return res.status(500).json({error:'Server error'});
    const visible = rows.map(r=>({
      id: r.id,
      text: r.is_hidden ? '[hidden by moderator]' : r.text,
      created_at: r.created_at,
      user: { id: r.user_id, name: r.user_name }
    }));
    res.json({ comments: visible });
  });
});

// Simple info
app.get('/api/info', (req,res)=> res.json({ name: 'SitusLayar22' }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Server running on', PORT));
