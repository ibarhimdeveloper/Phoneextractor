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
import { open } from 'sqlite';
import speakeasy from 'speakeasy';
import winston from 'winston';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import axios from 'axios';
import cors from 'cors';
import bodyParser from 'body-parser';
import { parsePhoneNumberFromString } from 'libphonenumber-js';
import { MongoClient } from 'mongodb';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import cookieParser from 'cookie-parser';

app.set('trust proxy', true);

let mongoDb;

// For __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// Activate Puppeteer stealth plugin
puppeteer.use(StealthPlugin());

// API Keys
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const NUMVERIFY_API_KEY = process.env.NUMVERIFY_API_KEY;
const TWO_CAPTCHA_API_KEY = process.env.TWO_CAPTCHA_API_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin112122';

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? 'https://phoneextractor.onrender.com' 
      : 'http://localhost:3000',
    methods: ['GET', 'POST']
  }
});

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
  '--no-zygote',
  '--disable-software-rasterizer',
'--disable-features=VizDisplayCompositor'
];

// Database connections
const mongoClient = new MongoClient(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
  retryWrites: true,
  retryReads: true
});

// SQLite database setup
let sqliteDb;
(async () => {
  sqliteDb = await open({
    filename: './app.db',
    driver: sqlite3.Database
  });
  
  await sqliteDb.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      revoked BOOLEAN DEFAULT 0,
      ip_whitelist TEXT,
      tfa_secret TEXT
    )
  `);

  
  await sqliteDb.run('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)');
  await sqliteDb.run('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)');
})();

async function connectMongoDB() {
  try {
    await mongoClient.connect();
    mongoDb = mongoClient.db();
    
    await mongoDb.collection('users').createIndex({ username: 1 }, { unique: true });
    
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin112122';
    const hash = await bcrypt.hash(adminPassword, 12);
    
    const result = await mongoDb.collection('users').updateOne(
      { username: 'admin' },
      { 
        $set: { 
          password_hash: hash,
          role: 'admin',
          updated_at: new Date()
        },
        $setOnInsert: {
          username: 'admin',
          created_at: new Date(),
          expires_at: null,
          revoked: false,
          ip_whitelist: null,
          tfa_secret: null
        }
      },
      { upsert: true }
    );
    
    if (result.upsertedCount > 0) {
      logger.info('Admin user created');
    }
  } catch (err) {
    logger.error('MongoDB connection error:', err);
    process.exit(1); // Exit if we can't connect to MongoDB
  }
}

connectMongoDB();


// Middleware
app.use(cookieParser());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://phoneextractor.onrender.com' 
    : 'http://localhost:3000',
  credentials: true, // Allow credentials
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.stack}`);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
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

// JWT configuration
const jwtConfig = {
  secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  expiresIn: '1h', // Increased from 30m
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000 // 1 hour in milliseconds
  }
};

// Socket.io events
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);

  socket.on('save-proxies', (proxies) => {
    proxyList = proxies.filter(proxy => isValidProxy(proxy));
    logger.info(`Saved ${proxyList.length} valid proxies`);
    socket.emit('proxies-saved', { count: proxyList.length });
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
function isValidProxy(proxy) {
  if (!proxy || typeof proxy !== 'string') return false;
  
  // Basic format validation
  const proxyRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}(:.+:.+)?$/;
  if (!proxyRegex.test(proxy)) return false;
  
  // Validate IP parts
  const ip = proxy.split(':')[0];
  const ipParts = ip.split('.');
  
  if (ipParts.length !== 4) return false;
  
  return ipParts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255 && part === num.toString();
  });
}

function getRandomProxy() {
  if (!proxyList || proxyList.length === 0) return null;
  const validProxies = proxyList.filter(p => isValidProxy(p));
  if (validProxies.length === 0) return null;
  return validProxies[Math.floor(Math.random() * validProxies.length)];
}

// In your server code (app.js)
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
  const proxy = getRandomProxy();
  const argsWithProxy = proxy 
    ? [...args, `--proxy-server=${proxy}`]
    : args;

  try {
    const browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu'
      ],
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser'
    });
    
    logger.info('Browser launched successfully');
    activeBrowsers[socketId] = browser;
    return browser;
  } catch (err) {
    logger.error(`Browser launch failed: ${err.message}`);
    if (attempt < 3) {
      await new Promise(res => setTimeout(res, 2000 * attempt));
      return startBrowser(socketId, attempt + 1);
    }
    throw err;
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

// Update admin login endpoint
app.post('/admin-login', async (req, res) => {
  const { password } = req.body;

  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign(
      { 
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour expiration
      }, 
      jwtConfig.secret
    );
    res.cookie('jwt', token, jwtConfig.cookieOptions);
    return res.json({ success: true });
  } else {
    return res.status(401).json({ success: false, error: 'Wrong password' });
  }
});

// Add this to your existing app.js
app.get('/check-auth', async (req, res) => {
  const token = req.cookies?.jwt;
  if (!token) {
    return res.status(401).json({ success: false, error: 'Not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, jwtConfig.secret);

    const user = await mongoDb.collection('users').findOne({
      username: decoded.username,
      revoked: { $ne: true },
      $or: [
        { expires_at: null },
        { expires_at: { $gt: new Date() } }
      ]
    });

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid or expired user' });
    }

    return res.json({
      success: true,
      user: {
        username: user.username,
        role: user.role || 'user'
      }
    });
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
});

// Verify Admin Middleware
function verifyAdmin(req, res, next) {
  const token = req.cookies.jwt;
  if (!token) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const decoded = jwt.verify(token, jwtConfig.secret);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired' });
    }
    res.status(403).json({ error: 'Invalid token' });
  }
}

// CAPTCHA solving
async function solveCaptcha(page) {
  try {
    const frames = page.frames();
    const recaptchaFrame = frames.find(frame => frame.url().includes('api2/anchor'));

    if (!recaptchaFrame) {
      logger.info('No CAPTCHA found.');
      return false;
    }

    logger.info('CAPTCHA detected. Solving...');
    const sitekey = await recaptchaFrame.$eval('#recaptcha-anchor', el => el.getAttribute('data-sitekey'));
    const url = page.url();

    const captchaIdResponse = await axios.get(
      `http://2captcha.com/in.php?key=${TWO_CAPTCHA_API_KEY}&method=userrecaptcha&googlekey=${sitekey}&pageurl=${encodeURIComponent(url)}&json=1`
    );
    
    if (!captchaIdResponse.data || !captchaIdResponse.data.request) {
      throw new Error('Failed to get CAPTCHA ID');
    }
    
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
      throw new Error('Failed to solve CAPTCHA after multiple attempts');
    }

    logger.info('CAPTCHA solved successfully.');
    await page.evaluate(`document.getElementById("g-recaptcha-response").innerHTML="${token}";`);
    await page.evaluate(() => {
      const form = document.querySelector('form');
      if (form) form.submit();
    });

    await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 30000 });
    return true;
  } catch (err) {
    logger.error(`CAPTCHA solving error: ${err.message}`);
    return false;
  }
}

// Generic scraper helper
async function genericScraper({ searchUrl, sourceName, searchTerm, location, pages, socketId, customExtraction }) {
  const seenNumbers = new Set();
  logger.info(`Starting ${sourceName} scrape`, { searchTerm, location, pages });
  
  const browser = await startBrowser(socketId);
  if (!browser) {
    throw new Error('Failed to start browser');
  }

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
    logger.error(`${params.sourceName} error: ${err.message}`);
    if (activeBrowsers[params.socketId]) {
      await activeBrowsers[params.socketId].close();
      delete activeBrowsers[params.socketId];
    }
    emitError(params.socketId, `Failed to scrape ${params.sourceName}: ${err.message}`);
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

// Replace SQLite code with MongoDB
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await mongoDb.collection('users').findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    // Check if account is active and not expired
    if (user.revoked || (user.expires_at && new Date(user.expires_at) < new Date())) {
      return res.status(401).json({ error: 'Account expired or revoked' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign(
      { 
        sub: user._id, 
        username: user.username, 
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour expiration
      },
      jwtConfig.secret
    );
    
    res.cookie('jwt', token, jwtConfig.cookieOptions);
    res.json({ 
      success: true,
      username: user.username,
      expiresAt: user.expires_at
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add logout endpoint
app.post('/logout', (req, res) => {
  res.clearCookie('jwt', jwtConfig.cookieOptions);
  res.json({ success: true });
});

app.post('/verify-numbers', async (req, res) => {
  const { numbers = [] } = req.body;
  if (!Array.isArray(numbers) || numbers.length === 0) {
    return res.status(400).json({ success: false, error: 'No numbers provided' });
  }

  const results = [];
  const NUMVERIFY_API_KEY = process.env.NUMVERIFY_API_KEY;
  
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

app.post('/generate-credentials', verifyAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    const generatedUsername = username || 'user' + crypto.randomBytes(3).toString('hex');
    const generatedPassword = crypto.randomBytes(6).toString('base64').slice(0, 10);
    const passwordHash = await bcrypt.hash(generatedPassword, 12);
    
    // Set expiry date (e.g., 14 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 14);

    await mongoDb.collection('users').insertOne({
      username: generatedUsername,
      password_hash: passwordHash,
      role: 'user',
      created_at: new Date(),
      expires_at: expiresAt,
      revoked: false,
      isActive: true
    });

    res.json({ 
      success: true, 
      username: generatedUsername, 
      password: generatedPassword,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
  });
  } catch (err) {
    logger.error('Credential Generation Error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/get-credentials', verifyAdmin, async (req, res) => {
  try {
    const users = await mongoDb.collection('users')
      .find({ role: 'user' })
      .sort({ created_at: -1 })
      .toArray();
      
    // Don't send password hashes to client
    const credentials = users.map(user => ({
      username: user.username,
      created_at: user.created_at,
      expires_at: user.expires_at,
      isActive: !user.revoked && (!user.expires_at || new Date(user.expires_at) > new Date())
    }));
    
    res.json({ success: true, credentials });
  } catch (err) {
    logger.error('Get credentials error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/toggle-credential', verifyAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    await mongoDb.collection('users').updateOne(
      { username },
      { $set: { revoked: req.body.revoke } }
    );
    res.json({ success: true });
  } catch (err) {
    logger.error('Toggle credential error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.post('/extend-credential', verifyAdmin, async (req, res) => {
  try {
    const { username, days = 7 } = req.body;
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + parseInt(days));
    
    await mongoDb.collection('users').updateOne(
      { username },
      { $set: { expires_at: expiresAt } }
    );
    
    res.json({ success: true, expiresAt });
  } catch (err) {
    logger.error('Extend credential error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Real-time extraction
app.post('/start-extraction', (req, res) => {
  const { source, term, location, pages } = req.body;

  logger.info(`Starting real-time extraction: ${source}, ${term}, ${location}, pages=${pages}`);
  res.json({ success: true, message: 'Extraction started' });

  let count = 0;
  const max = pages || 3;

  const interval = setInterval(() => {
    if (count >= max) {
      io.emit('extraction-complete', { total: count });
      clearInterval(interval);
      return;
    }

    const result = {
      phone: `+12345678${count}${count}`,
      source,
      type: 'Business',
      country: 'US',
      carrier: count % 2 === 0 ? 'AT&T' : 'T-Mobile',
      status: 'Valid'
    };

    io.emit('extraction-result', result);
    count++;
  }, 1000);
});

// Start server
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
server.listen(PORT, HOST, () => {
  logger.info(`Server running on http://${HOST}:${PORT}`);
});