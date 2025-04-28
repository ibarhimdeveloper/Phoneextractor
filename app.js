import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import crypto from 'crypto';
import sqlite3 from 'sqlite3';
import speakeasy from 'speakeasy';
import winston from 'winston';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import axios from 'axios';
import cors from 'cors';
import bodyParser from 'body-parser';
import { parsePhoneNumberFromString } from 'libphonenumber-js';

import { fileURLToPath } from 'url';
import { dirname } from 'path';

// For __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Activate Puppeteer stealth plugin
puppeteer.use(StealthPlugin());

// API Keys
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const NUMVERIFY_API_KEY = process.env.NUMVERIFY_API_KEY;

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const proxy = '';
const MAX_PARALLEL_TABS = 20;
const activeBrowsers = {};
let proxyList = []; // Global array to store proxies

// Browser launch args
const args = [
  '--disable-gpu',
  '--disable-dev-shm-usage',
  '--disable-setuid-sandbox',
  '--no-first-run',
  '--no-sandbox',
  '--no-zygote'
];

// Database setup
const db = new sqlite3.Database('./app.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Database connected successfully.');
  }
});

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

// Close database on process exit
process.on('exit', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database closed.');
    }
  });
});

// Middleware setup
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://phoneextractor.onrender.com' 
    : 'http://localhost:3000',
  credentials: true, // <<<<< ADD COMMA HERE
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


app.use(bodyParser.json());
app.use(express.static('public'));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.stack}`);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

const scrapeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5
});

const smsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10
});

app.use(limiter);
app.post(/\/scrape-.*/, scrapeLimiter);

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

// Socket.io events
io.on('connection', (socket) => {
  console.log('Client connected');

  socket.on('save-proxies', (proxies) => {
    proxyList = proxies;
    console.log(`Saved ${proxies.length} proxies`);
  });

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
function getRandomProxy(proxies) {
  if (!proxies || proxies.length === 0) return null;
  const randomIndex = Math.floor(Math.random() * proxies.length);
  return proxies[randomIndex];
}

function emitPhoneNumber(socketId, number, source) {
  if (!activeBrowsers[socketId]) return;
  io.to(socketId).emit('phoneNumber', { number, source });
}

function emitError(socketId, message) {
  io.to(socketId).emit('error', message);
}

function reportProgress(socketId, percent) {
  io.to(socketId).emit('progress', percent);
}

async function startBrowser(socketId, attempt = 1) {
  try {
    const proxy = getRandomProxy(proxyList);
    const browserArgs = [...args];

    if (proxy) {
      browserArgs.push(`--proxy-server=${proxy}`);
      logger.info(`Using proxy for ${socketId}: ${proxy}`);
    }

    const browser = await puppeteer.launch({ 
      headless: true,
      args: browserArgs
    });

    activeBrowsers[socketId] = browser;
    logger.info(`Browser launched successfully for socket: ${socketId}`);
    return browser;
    
  } catch (err) {
    logger.error(`Browser launch failed for socket ${socketId} on attempt ${attempt}: ${err.message}`);
    if (attempt < 5) {
      logger.warn(`Retrying browser launch for ${socketId} (attempt ${attempt + 1})...`);
      await new Promise((res) => setTimeout(res, 2000));
      return await startBrowser(socketId, attempt + 1);
    } else {
      logger.error(`Failed to launch browser after 5 attempts for ${socketId}`);
      emitError(socketId, 'Failed to start browser after multiple proxy attempts.');
      return null;
    }
  }
}

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

// CAPTCHA solving
async function solveCaptcha(page) {
  try {
    const frames = page.frames();
    const recaptchaFrame = frames.find(frame => frame.url().includes('api2/anchor'));

    if (!recaptchaFrame) {
      logger.info('No CAPTCHA found.');
      return;
    }

    logger.info('CAPTCHA detected. Solving...');
    const sitekey = await recaptchaFrame.$eval('#recaptcha-anchor', el => el.getAttribute('data-sitekey'));
    const url = page.url();

    const captchaIdResponse = await axios.get(
      `http://2captcha.com/in.php?key=${TWO_CAPTCHA_API_KEY}&method=userrecaptcha&googlekey=${sitekey}&pageurl=${encodeURIComponent(url)}&json=1`
    );
    const captchaId = captchaIdResponse.data.request;

    await new Promise(resolve => setTimeout(resolve, 20000));

    let token;
    for (let i = 0; i < 20; i++) {
      const res = await axios.get(
        `http://2captcha.com/res.php?key=${TWO_CAPTCHA_API_KEY}&action=get&id=${captchaId}&json=1`
      );
      if (res.data.status === 1) {
        token = res.data.request;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    if (!token) {
      logger.error('Failed to solve CAPTCHA.');
      return;
    }

    logger.info('CAPTCHA solved successfully.');
    await page.evaluate(`document.getElementById("g-recaptcha-response").innerHTML="${token}";`);
    await page.evaluate(() => {
      document.querySelector('form').submit();
    });

    await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 30000 });
  } catch (err) {
    logger.error(`CAPTCHA solving error: ${err.message}`);
  }
}

// Generic scraper helper
async function genericScraper({ searchUrl, sourceName, searchTerm, location, pages, socketId, customExtraction }) {
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const seenNumbers = new Set();

  try {
    const totalPages = Math.min(pages, 10); // Limit to 10 pages max
    const batchSize = Math.min(MAX_PARALLEL_TABS, 5); // Smaller batches for stability

    for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
      const url = searchUrl(searchTerm, location, pageNum);
      const page = await browser.newPage();
      
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        await solveCaptcha(page);

        let content;
        if (customExtraction) {
          content = await customExtraction(page);
        } else {
          content = await page.content();
        }

        const numbers = extractPhoneNumbers(content);
        numbers.forEach(number => {
          if (!seenNumbers.has(number)) {
            seenNumbers.add(number);
            emitPhoneNumber(socketId, number, sourceName);
          }
        });

        reportProgress(socketId, Math.round((pageNum / totalPages) * 100));
        await new Promise(resolve => setTimeout(resolve, 2000)); // Delay between pages
      } catch (err) {
        logger.error(`${sourceName} page ${pageNum} error: ${err.message}`);
      } finally {
        await page.close();
      }
    }

    reportProgress(socketId, 100);
  } catch (err) {
    logger.error(`${sourceName} error: ${err.message}`);
    emitError(socketId, `Failed to scrape ${sourceName}.`);
  } finally {
    if (browser && browser.isConnected()) {
      await browser.close();
    }
    delete activeBrowsers[socketId];
  }
}

// Individual scraper functions
async function scrapeYellowPages(params) {
  return genericScraper({
    searchUrl: (term, loc, page) => 
      `https://www.yellowpages.com/search?search_terms=${encodeURIComponent(term)}&geo_location_terms=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'YellowPages',
    ...params
  });
}

async function scrapeYelp(params) {
  return genericScraper({
    searchUrl: (term, loc, page) => 
      `https://www.yelp.com/search?find_desc=${encodeURIComponent(term)}&find_loc=${encodeURIComponent(loc)}&start=${(page-1)*10}`,
    sourceName: 'Yelp',
    ...params
  });
}

async function scrapePersonal({ name, socketId }) {
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const seenNumbers = new Set();

  try {
    const page = await browser.newPage();
    const url = `https://www.google.com/search?q=${encodeURIComponent(name)}+phone+number`;
    
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await solveCaptcha(page);

    const content = await page.content();
    const numbers = extractPhoneNumbers(content);
    
    numbers.forEach(number => {
      if (!seenNumbers.has(number)) {
        seenNumbers.add(number);
        emitPhoneNumber(socketId, number, 'Google');
      }
    });

    reportProgress(socketId, 100);
  } catch (err) {
    logger.error(`Personal search error: ${err.message}`);
    emitError(socketId, 'Failed to scrape personal search.');
  } finally {
    if (browser && browser.isConnected()) {
      await browser.close();
    }
    delete activeBrowsers[socketId];
  }
}

// Additional scraper functions (following same pattern)
async function scrapeWhitePages(params) {
  return genericScraper({
    searchUrl: (term, loc, page) => 
      `https://www.whitepages.com/name/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'WhitePages',
    ...params
  });
}

async function scrapeLinkedin(params) {
  return genericScraper({
    searchUrl: (term, loc, page) => 
      `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(term)}&location=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'LinkedIn',
    ...params,
    customExtraction: async (page) => {
      await page.waitForSelector('.entity-result__content', { timeout: 10000 });
      return await page.$$eval('.entity-result__content', els => 
        els.map(el => el.textContent)
      );
    }
  });
}

async function scrapeCustom({ url, depth = 1, socketId }) {
  const batchSize = 20;
  const browser = await startBrowser(socketId);
  if (!browser) return;
  const visited = new Set();
  const queue = [url];
  const seenNumbers = new Set();
  let crawledCount = 0;

  try {
    while (queue.length && crawledCount < depth) {
      const batch = queue.splice(0, batchSize);

      const batchResults = await Promise.all(batch.map(async (currentUrl) => {
        return await scrapeSingleUrl({ currentUrl, visited, seenNumbers, browser, socketId });
      }));

      batchResults.forEach(({ hrefs }) => {
        hrefs.forEach((href) => {
          if (!visited.has(href) && queue.length + visited.size < depth) {
            queue.push(href);
          }
        });
      });

      crawledCount = visited.size;
      reportProgress(socketId, Math.min((crawledCount / depth) * 100, 100));
      await new Promise((res) => setTimeout(res, 1000)); // small pause
    }

    reportProgress(socketId, 100); // Final 100%
  } catch (err) {
    logger.error(`Custom scrape error: ${err.message}`);
    emitError(socketId, 'Failed to scrape custom URL.');
  } finally {
    if (browser && browser.isConnected()) {
      await browser.close();
    }
    delete activeBrowsers[socketId];
  }
}

// Helper
async function scrapeSingleUrl({ currentUrl, visited, seenNumbers, browser, socketId }) {
  if (visited.has(currentUrl)) return { hrefs: [] };

  const page = await browser.newPage();
  const hrefs = [];

  try {
    await page.goto(currentUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await solveCaptcha(page);

    const content = await page.content();
    const numbers = extractPhoneNumbers(content);

    numbers.forEach((number) => {
      if (!seenNumbers.has(number)) {
        seenNumbers.add(number);
        emitPhoneNumber(socketId, number, 'Custom');
      }
    });

    const links = await page.$$eval('a', links =>
      links.map(link => link.href).filter(href => href.startsWith('http'))
    );
    hrefs.push(...links);
    visited.add(currentUrl);
  } catch (e) {
    logger.warn(`Failed to visit ${currentUrl}: ${e.message}`);
  } finally {
    await page.close();
  }

  return { hrefs };
}

async function scrapeManta({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.manta.com/search?search_source=nav&search=${encodeURIComponent(term)}&location=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'Manta',
    searchTerm, location, pages, socketId
  });
}

async function scrapeBBB({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.bbb.org/search?find_country=USA&find_text=${encodeURIComponent(term)}&find_loc=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'BBB',
    searchTerm, location, pages, socketId
  });
}

async function scrapeHotfrog({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.hotfrog.com/search/${encodeURIComponent(loc)}/${encodeURIComponent(term)}?page=${page}`,
    sourceName: 'Hotfrog',
    searchTerm, location, pages, socketId
  });
}

async function scrapeFoursquare({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://foursquare.com/v/search?near=${encodeURIComponent(loc)}&query=${encodeURIComponent(term)}&page=${page}`,
    sourceName: 'Foursquare',
    searchTerm, location, pages, socketId
  });
}

async function scrapeBrownbook({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.brownbook.net/businesses/?what=${encodeURIComponent(term)}&where=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'Brownbook',
    searchTerm, location, pages, socketId
  });
}

async function scrapeCityfos({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.cityfos.com/company/${encodeURIComponent(term)}-in-${encodeURIComponent(loc)}-${page}.htm`,
    sourceName: 'Cityfos',
    searchTerm, location, pages, socketId
  });
}

async function scrapeCylex({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.cylex.us.com/${encodeURIComponent(loc)}/${encodeURIComponent(term)}.html?page=${page}`,
    sourceName: 'Cylex',
    searchTerm, location, pages, socketId
  });
}

async function scrapeMerchantCircle({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.merchantcircle.com/search?q=${encodeURIComponent(term)}&loc=${encodeURIComponent(loc)}&start=${(page-1)*10}`,
    sourceName: 'MerchantCircle',
    searchTerm, location, pages, socketId
  });
}

async function scrapeLocalstack({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.localstack.com/search?find_desc=${encodeURIComponent(term)}&find_loc=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'Localstack',
    searchTerm, location, pages, socketId
  });
}
// Facebook Scraper
async function scrapeFacebook({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.facebook.com/public/${encodeURIComponent(term)}-${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'Facebook',
    searchTerm, location, pages, socketId
  });
}

// TruePeopleSearch Scraper
async function scrapeTruePeopleSearch({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.truepeoplesearch.com/results?name=${encodeURIComponent(term)}&citystatezip=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'TruePeopleSearch',
    searchTerm, location, pages, socketId
  });
}

// AnyWho Scraper
async function scrapeAnywho({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.anywho.com/people/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'AnyWho',
    searchTerm, location, pages, socketId
  });
}

// Spokeo Scraper
async function scrapeSpokeo({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.spokeo.com/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'Spokeo',
    searchTerm, location, pages, socketId
  });
}

// FastPeopleSearch Scraper
async function scrapeFastPeopleSearch({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.fastpeoplesearch.com/name/${encodeURIComponent(term)}_${encodeURIComponent(loc)}_${page}`,
    sourceName: 'FastPeopleSearch',
    searchTerm, location, pages, socketId
  });
}

// 411 Scraper
async function scrape411({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.411.com/name/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: '411',
    searchTerm, location, pages, socketId
  });
}

// USPhonebook Scraper
async function scrapeUsPhonebook({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.usphonebook.com/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'USPhonebook',
    searchTerm, location, pages, socketId
  });
}

// Radaris Scraper
async function scrapeRadaris({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://radaris.com/p/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'Radaris',
    searchTerm, location, pages, socketId
  });
}

// ZabaSearch Scraper
async function scrapeZabaSearch({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.zabasearch.com/people/${encodeURIComponent(term)}/${encodeURIComponent(loc)}/${page}`,
    sourceName: 'ZabaSearch',
    searchTerm, location, pages, socketId
  });
}

// PeopleFinders Scraper
async function scrapePeopleFinders({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.peoplefinders.com/name/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'PeopleFinders',
    searchTerm, location, pages, socketId
  });
}

// PeekYou Scraper
async function scrapePeekyou({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.peekyou.com/usa/${encodeURIComponent(loc)}/${encodeURIComponent(term)}/${page}`,
    sourceName: 'PeekYou',
    searchTerm, location, pages, socketId
  });
}

// ThatsThem Scraper
async function scrapeThatsThem({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://thatsthem.com/name/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'ThatsThem',
    searchTerm, location, pages, socketId
  });
}

// Addresses Scraper
async function scrapeAddresses({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://www.addresses.com/people/${encodeURIComponent(term)}/${encodeURIComponent(loc)}?page=${page}`,
    sourceName: 'Addresses',
    searchTerm, location, pages, socketId
  });
}

// Pipl Scraper
async function scrapePipl({ searchTerm, location, pages, socketId }) {
  await genericScraper({
    searchUrl: (term, loc, page) => `https://pipl.com/search/?q=${encodeURIComponent(term)}+${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'Pipl',
    searchTerm, location, pages, socketId
  });
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
      scrapePersonal({ name: `${searchTerm} ${location}`, socketId }),
      scrapeManta({ searchTerm, location, pages, socketId }),
      scrapeBBB({ searchTerm, location, pages, socketId }),
      scrapeHotfrog({ searchTerm, location, pages, socketId }),
      scrapeFoursquare({ searchTerm, location, pages, socketId }),
      scrapeBrownbook({ searchTerm, location, pages, socketId }),
      scrapeCityfos({ searchTerm, location, pages, socketId }),
      scrapeCylex({ searchTerm, location, pages, socketId }),
      scrapeMerchantCircle({ searchTerm, location, pages, socketId }),
      scrapeLocalstack({ searchTerm, location, pages, socketId }),
      scrapeWhitePages({ searchTerm, location, pages, socketId }),
      scrapeLinkedin({ searchTerm, location, pages, socketId }),
      scrapeFacebook({ searchTerm, location, pages, socketId }),
      scrapeTruePeopleSearch({ searchTerm, location, pages, socketId }),
      scrapeAnywho({ searchTerm, location, pages, socketId }),
      scrapeSpokeo({ searchTerm, location, pages, socketId }),
      scrapeFastPeopleSearch({ searchTerm, location, pages, socketId }),
      scrape411({ searchTerm, location, pages, socketId }),
      scrapeUsPhonebook({ searchTerm, location, pages, socketId }),
      scrapeRadaris({ searchTerm, location, pages, socketId }),
      scrapeZabaSearch({ searchTerm, location, pages, socketId }),
      scrapePeopleFinders({ searchTerm, location, pages, socketId }),
      scrapePeekyou({ searchTerm, location, pages, socketId }),
      scrapeThatsThem({ searchTerm, location, pages, socketId }),
      scrapeAddresses({ searchTerm, location, pages, socketId }),
      scrapePipl({ searchTerm, location, pages, socketId })
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
  const NUMVERIFY_API_KEY = '';
  
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

// WhitePages Endpoint
app.post('/scrape-whitepages', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeWhitePages({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-whitepages: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape WhitePages.' });
  }
});

// LinkedIn Endpoint
app.post('/scrape-linkedin', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeLinkedin({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-linkedin: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape LinkedIn.' });
  }
});

// Add similar endpoints for all other scrapers following the same pattern
app.post('/scrape-facebook', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeFacebook({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-facebook: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Facebook.' });
  }
});

app.post('/scrape-truepeoplesearch', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeTruePeopleSearch({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-truepeoplesearch: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape TruePeopleSearch.' });
  }
});

app.post('/scrape-anywho', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeAnywho({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-anywho: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Anywho.' });
  }
});

app.post('/scrape-spokeo', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeSpokeo({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-spokeo: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Spokeo.' });
  }
});

app.post('/scrape-fastpeoplesearch', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeFastPeopleSearch({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-fastpeoplesearch: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape FastPeopleSearch.' });
  }
});

app.post('/scrape-411', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrape411({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-411: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape 411.' });
  }
});

app.post('/scrape-usphonebook', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeUsPhonebook({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-usphonebook: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape USPhonebook.' });
  }
});

app.post('/scrape-radaris', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeRadaris({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-radaris: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Radaris.' });
  }
});

app.post('/scrape-zabasearch', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeZabaSearch({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-zabasearch: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape ZabaSearch.' });
  }
});

app.post('/scrape-peoplefinders', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapePeopleFinders({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-peoplefinders: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape PeopleFinders.' });
  }
});

app.post('/scrape-peekyou', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapePeekyou({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-peekyou: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Peekyou.' });
  }
});

app.post('/scrape-thatsthem', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeThatsThem({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-thatsthem: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape ThatsThem.' });
  }
});

app.post('/scrape-addresses', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapeAddresses({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-addresses: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Addresses.' });
  }
});

app.post('/scrape-pipl', async (req, res) => {
  const { searchTerm, location, pages, socketId } = req.body;
  if (!searchTerm || !location || !pages || !socketId) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  try {
    await scrapePipl({ searchTerm, location, pages, socketId });
    res.json({ success: true });
  } catch (err) {
    logger.error(`API error for /scrape-pipl: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to scrape Pipl.' });
  }
});

// SMS endpoint
app.post('/send-verification-sms', smsLimiter, async (req, res) => {
  try {
    const { bulk, phoneNumber, code } = req.body;
    const apiUrl = 'https://api.brevo.com/v3/transactionalSMS/sms';
    const headers = {
      'api-key': process.env.BREVO_API_KEY,
      'Content-Type': 'application/json'
    };

    if (Array.isArray(bulk)) {
      if (bulk.length > 100) {
        return res.status(400).json({ success: false, error: 'Max 100 numbers per batch' });
      }

      const results = [];
      for (const item of bulk) {
        try {
          const response = await axios.post(apiUrl, {
            sender: "PhoneExtractor",
            recipient: item.number,
            content: item.message,
            type: "transactional"
          }, { headers, timeout: 10000 });
          results.push({ number: item.number, success: true });
        } catch (err) {
          results.push({ number: item.number, success: false, error: err.message });
        }
        await new Promise(resolve => setTimeout(resolve, 500)); // Rate limiting
      }
      return res.json({ success: true, results });
    }

    if (phoneNumber && code) {
      const response = await axios.post(apiUrl, {
        sender: "PhoneExtractor",
        recipient: phoneNumber,
        content: `Your verification code is: ${code}`,
        type: "transactional"
      }, { headers, timeout: 10000 });
      return res.json({ success: true, response: response.data });
    }

    return res.status(400).json({ success: false, error: 'Invalid request' });
  } catch (err) {
    logger.error(`SMS error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Failed to send SMS' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});