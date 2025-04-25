const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const speakeasy = require('speakeasy');
const winston = require('winston');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Apply Puppeteer stealth plugin
puppeteer.use(StealthPlugin());

// Database setup
const db = new sqlite3.Database('./database.sqlite');

// Initialize database tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    revoked BOOLEAN DEFAULT 0,
    ip_whitelist TEXT,
    tfa_secret TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    user_id INTEGER,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Middleware setup
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// CSRF protection setup
const csrfTokens = new Map();
app.use((req, res, next) => {
  const token = crypto.randomBytes(16).toString('hex');
  res.locals.csrfToken = token;
  csrfTokens.set(token, Date.now() + 3600000);
  next();
});

// JWT configuration
const jwtConfig = {
  secret: crypto.randomBytes(64).toString('hex'),
  expiresIn: '30m',
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
};

// Create admin user if not exists
const adminPassword = 'Admin112122';
bcrypt.hash(adminPassword, 12, (err, hash) => {
  if (err) {
    logger.error('Error creating admin user:', err);
    return;
  }
  db.run(`INSERT OR IGNORE INTO users (username, password_hash, role) 
          VALUES (?, ?, ?)`, 
          ['admin', hash, 'admin'],
          (err) => {
            if (err) logger.error('Admin creation error:', err);
          });
});

// Socket.io setup
const activeBrowsers = {};
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);

  socket.on('cancelScrape', async () => {
    if (activeBrowsers[socket.id]) {
      try {
        await activeBrowsers[socket.id].close();
        delete activeBrowsers[socket.id];
        logger.info(`Scraping stopped for socket: ${socket.id}`);
      } catch (err) {
        logger.error(`Error closing browser for socket ${socket.id}: ${err.message}`);
        socket.emit('error', 'Failed to cancel the scraping operation.');
      }
    }
  });

  socket.on('disconnect', () => {
    if (activeBrowsers[socket.id]) {
      activeBrowsers[socket.id].close().catch((err) => {
        logger.error(`Error closing browser on disconnect for socket ${socket.id}: ${err.message}`);
      });
      delete activeBrowsers[socket.id];
    }
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

// Utility functions
function emitPhoneNumber(socketId, number, source) {
  if (!activeBrowsers[socketId]) return;
  io.to(socketId).emit('phoneNumber', { number, source });
}

function emitError(socketId, message) {
  io.to(socketId).emit('error', message);
}

async function startBrowser(socketId) {
  try {
    const browser = await puppeteer.launch({ 
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    activeBrowsers[socketId] = browser;
    logger.info(`Browser launched for socket: ${socketId}`);
    return browser;
  } catch (err) {
    logger.error(`Failed to launch browser for socket ${socketId}: ${err.message}`);
    emitError(socketId, 'Failed to start browser. Please try again later.');
    return null;
  }
}

const { parsePhoneNumberFromString } = require('libphonenumber-js');

function extractPhoneNumbers(text) {
  const phoneRegex = /(?:\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g;
  const matches = [...text.matchAll(phoneRegex)].map(m => m[1]);

  return matches.map(raw => {
    const number = parsePhoneNumberFromString(raw, 'US');
    if (number?.isValid()) {
      return number.number;
    }
    return null;
  }).filter(Boolean);
}

// Authentication middleware
function verifyAdmin(req, res, next) {
  const token = req.cookies.jwt;
  try {
    const decoded = jwt.verify(token, jwtConfig.secret);
    if (decoded.role !== 'admin') throw new Error();
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Admin access required' });
  }
}

// Admin endpoints
app.post('/api/admin/enable-2fa', verifyAdmin, (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20 });
  db.run('UPDATE users SET tfa_secret = ? WHERE id = ?', 
        [secret.base32, req.user.sub]);
  res.json({ secret: secret.base32, qrCode: secret.otpauth_url });
});

// Scraping functions
async function scrapeYellowPages({ searchTerm, location, pages, socketId }) {
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const page = await browser.newPage();
  const seenNumbers = new Set();

  try {
    for (let i = 1; i <= pages; i++) {
      const url = `https://www.yellowpages.com/search?search_terms=${encodeURIComponent(searchTerm)}&geo_location_terms=${encodeURIComponent(location)}&page=${i}`;
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      const content = await page.content();
      const numbers = extractPhoneNumbers(content);
      
      numbers.forEach((number) => {
        if (!seenNumbers.has(number)) {
          seenNumbers.add(number);
          emitPhoneNumber(socketId, number, 'YellowPages');
        }
      });
      await new Promise((res) => setTimeout(res, 1000));
    }
  } catch (err) {
    logger.error(`YellowPages error: ${err.message}`);
    emitError(socketId, 'Failed to scrape YellowPages.');
  } finally {
    await page.close();
    await browser.close();
    delete activeBrowsers[socketId];
  }
}

async function scrapeYelp({ searchTerm, location, pages, socketId }) {
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const page = await browser.newPage();
  const seenNumbers = new Set();

  try {
    for (let i = 0; i < pages; i++) {
      const offset = i * 10;
      const url = `https://www.yelp.com/search?find_desc=${encodeURIComponent(searchTerm)}&find_loc=${encodeURIComponent(location)}&start=${offset}`;
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      const content = await page.content();
      const numbers = extractPhoneNumbers(content);
      
      numbers.forEach((number) => {
        if (!seenNumbers.has(number)) {
          seenNumbers.add(number);
          emitPhoneNumber(socketId, number, 'Yelp');
        }
      });
      await new Promise((res) => setTimeout(res, 1000));
    }
  } catch (err) {
    logger.error(`Yelp error: ${err.message}`);
    emitError(socketId, 'Failed to scrape Yelp.');
  } finally {
    await page.close();
    await browser.close();
    delete activeBrowsers[socketId];
  }
}

async function scrapePersonal({ name, socketId }) {
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const page = await browser.newPage();
  const seenNumbers = new Set();

  try {
    const url = `https://www.google.com/search?q=${encodeURIComponent(name)}+phone+number`;
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    const content = await page.content();
    const numbers = extractPhoneNumbers(content);
    
    numbers.forEach((number) => {
      if (!seenNumbers.has(number)) {
        seenNumbers.add(number);
        emitPhoneNumber(socketId, number, 'Google');
      }
    });
  } catch (err) {
    logger.error(`Google personal search error: ${err.message}`);
    emitError(socketId, 'Failed to scrape Google.');
  } finally {
    await browser.close();
    delete activeBrowsers[socketId];
  }
}

async function scrapeCustom({ url, depth = 1, socketId }) {
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const visited = new Set();
  const queue = [url];
  const seenNumbers = new Set();

  try {
    while (queue.length && visited.size < depth) {
      const currentUrl = queue.shift();
      if (!currentUrl || visited.has(currentUrl)) continue;
      visited.add(currentUrl);
      const page = await browser.newPage();
      try {
        await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        const content = await page.content();
        const numbers = extractPhoneNumbers(content);
        
        numbers.forEach((number) => {
          if (!seenNumbers.has(number)) {
            seenNumbers.add(number);
            emitPhoneNumber(socketId, number, 'Custom');
          }
        });

        const hrefs = await page.$$eval('a', links =>
          links.map(link => link.href).filter(href => href.startsWith('http'))
        );
        hrefs.forEach((href) => {
          if (!visited.has(href) && queue.length < depth) queue.push(href);
        });
      } catch (e) {
        logger.warn(`Failed to visit ${currentUrl}: ${e.message}`);
      } finally {
        await page.close();
      }
    }
  } catch (err) {
    logger.error(`Custom scrape error: ${err.message}`);
    emitError(socketId, 'Failed to scrape custom URL.');
  } finally {
    await browser.close();
    delete activeBrowsers[socketId];
  }
}

// API endpoints
app.post('/scrape-global', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;

  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await Promise.all([
      scrapeYellowPages({ searchTerm, location, pages, socketId }),
      scrapeYelp({ searchTerm, location, pages, socketId }),
      scrapePersonal({ name: `${searchTerm} ${location}`, socketId })
    ]);
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-global: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed global scrape.' });
  }
});

app.post('/verify-numbers', async (req, res) => {
  const { numbers = [] } = req.body;
  if (!Array.isArray(numbers) || numbers.length === 0) {
    return res.status(400).json({ success: false, error: 'No numbers provided' });
  }

  const results = [];
  const NUMVERIFY_API_KEY = 'c929995ef8677c74d4881ed70ea1fb5a';
  
  for (const phone of numbers) {
    try {
      const response = await axios.get(
        `http://apilayer.net/api/validate?access_key=${NUMVERIFY_API_KEY}&number=${encodeURIComponent(phone)}&country_code=US&format=1`
      );
      if (response.data) {
        results.push({
          phone,
          valid: response.data.valid,
          type: response.data.line_type,
          carrier: response.data.carrier,
          country: response.data.country_name
        });
      }
    } catch (err) {
      logger.warn(`Verification failed for ${phone}: ${err.message}`);
      results.push({ phone, valid: false });
    }
  }

  res.json({ success: true, results });
});

app.post('/scrape-yellowpages', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeYellowPages({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-yellowpages: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape YellowPages.' });
  }
});

app.post('/scrape-yelp', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeYelp({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-yelp: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Yelp.' });
  }
});

app.post('/scrape-personal', async (req, res) => {
  const { name, socketId } = req.body;
  if (!name || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapePersonal({ name, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-personal: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Google personal search.' });
  }
});

app.post('/scrape-custom', async (req, res) => {
  const { url, depth, socketId } = req.body;
  if (!url || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeCustom({ url, depth, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-custom: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape custom URL.' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});