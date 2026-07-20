require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');
const { z } = require('zod');

const app = express();
const PORT = process.env.PORT || 4000;

// --- veritabanı (tek dosya, klasörsüz) ---
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'markadoner.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    guests INTEGER NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    note TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    rating INTEGER NOT NULL,
    comment TEXT NOT NULL,
    ai_reply TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// --- güvenlik ve istek gövdesi ayrıştırma ---
app.use(helmet({ contentSecurityPolicy: false })); // sayfa içi <script> kullandığımız için kapalı
app.use(express.json({ limit: '20kb' }));

const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: allowedOrigins.length ? allowedOrigins : true }));

const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çok fazla istek gönderildi, lütfen daha sonra tekrar deneyin.' },
});

// --- yönetici anahtarı doğrulaması ---
function requireAdminKey(req, res, next) {
  const provided = req.get('x-admin-key');
  const expected = process.env.ADMIN_API_KEY;
  if (!expected || expected === 'change-this-before-deploying') {
    return res.status(500).json({ error: 'Sunucu yapılandırması eksik: ADMIN_API_KEY ayarlanmamış.' });
  }
  if (!provided || provided !== expected) {
    return res.status(401).json({ error: 'Yetkisiz erişim.' });
  }
  next();
}

// --- doğrulama şeması ---
const reservationSchema = z.object({
  name: z.string().trim().min(2, 'Ad soyad çok kısa').max(120),
  phone: z.string().trim().min(7, 'Geçerli bir telefon giriniz').max(30),
  guests: z.coerce.number().int().min(1).max(100),
  date: z.string().trim().min(4).max(20),
  time: z.string().trim().min(3).max(10),
  note: z.string().trim().max(500).optional().or(z.literal('')),
});

const reviewSchema = z.object({
  name: z.string().trim().min(2, 'Ad soyad çok kısa').max(100),
  rating: z.coerce.number().int().min(1, 'Puan 1-5 arası olmalı').max(5, 'Puan 1-5 arası olmalı'),
  comment: z.string().trim().min(3, 'Yorum çok kısa').max(1000),
});

// Yorumlara Google
