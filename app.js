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
import { dirname, join } from 'path';
import cookieParser from 'cookie-parser';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerDefinition from './api-docs.js';

// Directory utils
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Puppeteer stealth plugin
puppeteer.use(StealthPlugin());

// Environment variables
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const NUMVERIFY_API_KEY = process.env.NUMVERIFY_API_KEY;
const TWO_CAPTCHA_API_KEY = process.env.TWO_CAPTCHA_API_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Express app setup
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

// Swagger docs setup
const specs = swaggerJsdoc({
  definition: swaggerDefinition,
  apis: ['./app.js'] // or wherever your route annotations live
});

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));


setInterval(() => {
  const memoryUsage = process.memoryUsage();
  logger.info(`Memory usage: 
    RSS: ${Math.round(memoryUsage.rss / 1024 / 1024)}MB 
    Heap: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB/${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`);
}, 60000);

setInterval(() => {
  logger.info(`Active browsers: ${Object.keys(activeBrowsers).length}`);
}, 30000);

// Trust proxy safely (only localhost)
app.set('trust proxy', 'loopback');

let mongoDb;
const MAX_CONCURRENT_SCRAPERS = 3;
let activeScrapers = 0;
let proxyIndex = 0;

const MAX_PARALLEL_TABS = 20;
const activeBrowsers = {};
let proxyList = [];

let formattedProxy = null;

if (proxyList.length > 0) {
  const proxy = proxyList[proxyIndex % proxyList.length];

  if (proxy && typeof proxy === 'string' && proxy.includes(':')) {
    const parts = proxy.split(':');
    const [host, port, username, password] = parts;

    if (host && port) {
      formattedProxy = (username && password)
        ? `http://${username}:${password}@${host}:${port}`
        : `http://${host}:${port}`;

      console.log('Selected proxy:', formattedProxy);
    }
  }
}


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
  retryReads: true,
  maxPoolSize: 50,
  minPoolSize: 10
});

// Add proxy caching
const proxyCache = new Map();
async function getHealthyProxy() {
  // Check cache first
  for (const [proxy, lastChecked] of proxyCache.entries()) {
    if (Date.now() - lastChecked < 300000) { // 5 minute cache
      return proxy;
    }
  }
  
  // Find a working proxy
  for (const proxy of proxyList) {
    if (await checkProxy(proxy)) {
      proxyCache.set(proxy, Date.now());
      return proxy;
    }
  }
  return null;
}

// Add proxy authentication support
const proxy = proxyList[proxyIndex];


// Update browser launch
const browser = await puppeteer.launch({
  args: [`--proxy-server=${formattedProxy}`, ...args],
});

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

// Middleware
app.use(cookieParser());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://phoneextractor.onrender.com' 
    : 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
}));

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.stack}`);
  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 ? 'Internal Server Error' : err.message;
  res.status(statusCode).json({ 
    success: false,
    error: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
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
  expiresIn: '8h',
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  }
};

// Session middleware
app.use((req, res, next) => {
  res.locals.user = null;
  const token = req.cookies?.jwt;
  if (token) {
    try {
      res.locals.user = jwt.verify(token, jwtConfig.secret);
    } catch (err) {
      res.clearCookie('jwt', jwtConfig.cookieOptions);
    }
  }
  next();
});

// If you're using WebSockets for progress updates
function setupSocketListeners() {
  socket.on('extraction-progress', (data) => {
    if (data.socketId === appState.socketId) {
      updateProgress(data.percent, data.message);
      
      // Complete the process if we reached 100%
      if (data.percent === 100) {
        setTimeout(() => {
          resetExtraction();
          showToast('Extraction completed!', 'success');
        }, 1000);
      }
    }
  });
  
  socket.on('extraction-error', (data) => {
    if (data.socketId === appState.socketId) {
      showToast(data.error, 'danger');
      resetExtraction();
    }
  });
}

// Connect to MongoDB
async function connectMongoDB() {
  try {
    await mongoClient.connect();
    mongoDb = mongoClient.db('phoneExtractor');
    console.log('✅ Connected to MongoDB');
    
    await mongoDb.collection('users').createIndex({ username: 1 }, { unique: true });
    await mongoDb.collection('extractions').createIndex({ userId: 1 });
    await mongoDb.collection('extractions').createIndex({ createdAt: -1 });
    
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
    process.exit(1);
  }
}

connectMongoDB();

// Utility functions
function isValidProxy(proxy) {
  if (!proxy || typeof proxy !== 'string') return false;
  const proxyRegex = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}(:.+:.+)?$/;
  if (!proxyRegex.test(proxy)) return false;
  const ip = proxy.split(':')[0];
  const ipParts = ip.split('.');
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

function emitPhoneNumber(socketId, number, source) {
  try {
    if (activeBrowsers[socketId]) {
      io.to(socketId).emit('phoneNumber', { number, source });
    }
  } catch (err) {
    logger.error(`Emit Error: ${err.message}`);
  }
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
    });
    
    logger.info('Browser launched successfully');
    activeBrowsers[socketId] = { browser, socket: io.sockets.sockets.get(socketId) };
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
  const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?:\s*(?:#|x\.?|ext\.?|extension)\s*\d+)?/gi;
  const matches = [...text.matchAll(phoneRegex)].map(m => m[1]);

  return matches.map(raw => {
    try {
      const number = parsePhoneNumberFromString(raw, 'US');
      return number?.formatInternational() || raw;
    } catch {
      return raw;  // Return raw value even if validation fails
    }
  }).filter(Boolean);
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  // Basic sanitization - remove script tags and other potentially dangerous content
  return input.replace(/<[^>]*>?/gm, '')
             .replace(/[&<>"'`=\/]/g, '')
             .trim();
}

// Socket.io connection handler
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);
  activeBrowsers[socket.id] = { socket };

  socket.on('save-proxies', (proxies) => {
    proxyList = proxies.filter(proxy => isValidProxy(proxy));
    logger.info(`Saved ${proxyList.length} valid proxies`);
    socket.emit('proxies-saved', { count: proxyList.length });
  });

  socket.on('start-extraction', async (data) => {
    try {
      const { source, searchTerm, location, pages } = data;
      const scraperFunction = getScraperFunction(source);
      if (scraperFunction) {
        await scraperFunction({ 
          searchTerm, 
          location, 
          pages, 
          socketId: socket.id 
        });
      }
    } catch (err) {
      logger.error(`Extraction error: ${err.message}`);
      socket.emit('error', err.message);
    }
  });

  socket.on('disconnect', () => {
    if (activeBrowsers[socket.id]?.browser) {
      activeBrowsers[socket.id].browser.close().catch(err => {
        logger.error(`Error closing browser: ${err.message}`);
      });
    }
    delete activeBrowsers[socket.id];
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

function getScraperFunction(source) {
  const scraperMap = {
    'yellowpages': scrapeYellowPages,
    'yelp': scrapeYelp,
    'personal': scrapePersonal,
    'custom': scrapeCustom,
    'whitepages': scrapeWhitePages,
    'linkedin': scrapeLinkedin,
    'facebook': scrapeFacebook,
    'truepeoplesearch': scrapeTruePeopleSearch,
    'anywho': scrapeAnywho,
    'spokeo': scrapeSpokeo,
    'fastpeoplesearch': scrapeFastPeopleSearch,
    '411': scrape411,
    'usphonebook': scrapeUsPhonebook,
    'radaris': scrapeRadaris,
    'zabasearch': scrapeZabaSearch,
    'peoplefinders': scrapePeopleFinders,
    'peekyou': scrapePeekyou,
    'thatsthem': scrapeThatsThem,
    'addresses': scrapeAddresses,
    'pipl': scrapePipl,
    'manta': scrapeManta,
    'bbb': scrapeBBB,
    'hotfrog': scrapeHotfrog,
    'foursquare': scrapeFoursquare,
    'brownbook': scrapeBrownbook,
    'cityfos': scrapeCityfos,
    'cylex': scrapeCylex,
    'merchantcircle': scrapeMerchantCircle,
    'localstack': scrapeLocalstack
  };
  
  return scraperMap[source];
}

// Generic scraper function
async function genericScraper({ searchUrl, sourceName, searchTerm, location, pages, socketId, customExtraction }) {
  if (activeScrapers >= MAX_CONCURRENT_SCRAPERS) {
    throw new Error('Maximum concurrent scrapers reached');
  }

  const seenNumbers = new Set();
  logger.info(`Starting ${sourceName} scrape`, { searchTerm, location, pages });
  
  const socket = activeBrowsers[socketId]?.socket;
  if (!socket) {
    throw new Error('No active socket connection');
  }

  const browser = await startBrowser(socketId);
  if (!browser) {
    throw new Error('Failed to start browser');
  }

  activeScrapers++;
  try {
    const totalPages = Math.min(pages, 10);
    
    for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
      const url = searchUrl(searchTerm, location, pageNum);
      const page = await browser.newPage();
      
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // Check for CAPTCHA and solve if needed
        const captchaSolved = await solveCaptcha(page);
        if (!captchaSolved) {
          throw new Error('CAPTCHA solving failed');
        }

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
            socket.emit('phoneNumber', { number, source: sourceName });
          }
        });

        const progress = Math.round((pageNum / totalPages) * 100);
        socket.emit('progress', progress);
        
        await new Promise(resolve => setTimeout(resolve, 2000));
      } catch (err) {
        logger.error(`${sourceName} page ${pageNum} error: ${err.message}`);
        socket.emit('error', `Page ${pageNum} failed: ${err.message}`);
      } finally {
        await page.goto(url, {
          waitUntil: 'networkidle2',
          timeout: 60000 
        });
      }
    }

    await page.waitForSelector('body', { timeout: 30000 });

    socket.emit('progress', 100);
  } catch (err) {
    logger.error(`Scraping Error: ${err.stack}`);
    socket.emit('error', {
      code: 'SCRAPE_FAILURE',
      message: `Failed to scrape ${sourceName}`,
      details: err.message
    });
    throw err;
  }
}

// Individual scraper functions
async function scrapeYellowPages(params) {
  return genericScraper({
    ...params,
    searchUrl: (term, loc, page) => 
      `https://www.yellowpages.com/search?search_terms=${encodeURIComponent(term)}&geo_location_terms=${encodeURIComponent(loc)}&page=${page}`,
    sourceName: 'YellowPages'
  });
}

async function scrapeYelp(params) {
  return genericScraper({
    ...params,
    searchUrl: (term, loc, page) => 
      `https://www.yelp.com/search?find_desc=${encodeURIComponent(term)}&find_loc=${encodeURIComponent(loc)}&start=${(page-1)*10}`,
    sourceName: 'Yelp'
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
  const searchTerm = sanitizeInput(req.body.searchTerm);

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

// Authentication middleware
function verifyUser(req, res, next) {
  const token = req.cookies?.jwt;
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, jwtConfig.secret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function verifyAdmin(req, res, next) {
  const token = req.cookies?.jwt;
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
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired' });
    }
    res.status(403).json({ error: 'Invalid token' });
  }
}

// API endpoints
app.post('/admin-login', async (req, res) => {
  const { password } = req.body;

  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign(
      { 
        role: 'admin',
        exp: Math.floor(Date.now() / 1000) + (60 * 60)
      }, 
      jwtConfig.secret
    );
    res.cookie('jwt', token, jwtConfig.cookieOptions);
    return res.json({ success: true });
  } else {
    return res.status(401).json({ success: false, error: 'Wrong password' });
  }
});

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

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await mongoDb.collection('users').findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.revoked || (user.expires_at && new Date(user.expires_at) < new Date())) {
      return res.status(403).json({ error: 'Account expired or revoked' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      {
        sub: user._id,
        username: user.username,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + (60 * 60)
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

app.post('/logout', (req, res) => {
  res.clearCookie('jwt', jwtConfig.cookieOptions);
  res.json({ success: true });
});

app.post('/verify-numbers', async (req, res) => {
  try {
    const { numbers = [] } = req.body;
    
    if (!Array.isArray(numbers) || numbers.length === 0) {
      throw { statusCode: 400, message: 'No numbers provided' };
    }
    
    if (numbers.length > 100) {
      throw { statusCode: 400, message: 'Maximum 100 numbers per request' };
    }

    const results = await Promise.all(
      numbers.map(async phone => {
        try {
          const response = await axios.get(
            `http://apilayer.net/api/validate?access_key=${NUMVERIFY_API_KEY}&number=${phone}&country_code=US&format=1`
          );
          return {
            phone,
            valid: response.data.valid,
            type: response.data.line_type,
            carrier: response.data.carrier,
            country: response.data.country_name
          };
        } catch (err) {
          return { phone, valid: false, error: err.message };
        }
      })
    );

    res.json({ success: true, results });
    
  } catch (err) {
    next(err);
  }
});

function sanitizeFields(body, fields) {
  const result = {};
  for (const field of fields) {
    result[field] = sanitizeInput(body[field]);
  }
  return result;
}

// Fix the createScrapeRoute function
function createScrapeRoute(scrapeFunction, requiredFields) {
  return async (req, res, next) => {
    try {
      const fields = sanitizeFields(req.body, requiredFields);
      for (const field of requiredFields) {
        if (
          fields[field] === undefined ||
          fields[field] === null ||
          (typeof fields[field] === 'string' && fields[field].trim() === '')
        ) {
          return res.status(400).json({ success: false, error: `Missing required field: ${field}` });
        }
      }

      await scrapeFunction(fields);
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  };
}

// Define each route
app.post('/scrape-yellowpages', createScrapeRoute(scrapeYellowPages, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-yelp', createScrapeRoute(scrapeYelp, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-personal', createScrapeRoute(scrapePersonal, ['name', 'socketId']));
app.post('/scrape-custom', createScrapeRoute(scrapeCustom, ['url', 'depth', 'socketId']));
app.post('/scrape-whitepages', createScrapeRoute(scrapeWhitePages, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-linkedin', createScrapeRoute(scrapeLinkedin, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-facebook', createScrapeRoute(scrapeFacebook, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-truepeoplesearch', createScrapeRoute(scrapeTruePeopleSearch, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-anywho', createScrapeRoute(scrapeAnywho, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-spokeo', createScrapeRoute(scrapeSpokeo, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-fastpeoplesearch', createScrapeRoute(scrapeFastPeopleSearch, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-411', createScrapeRoute(scrape411, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-usphonebook', createScrapeRoute(scrapeUsPhonebook, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-radaris', createScrapeRoute(scrapeRadaris, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-zabasearch', createScrapeRoute(scrapeZabaSearch, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-peoplefinders', createScrapeRoute(scrapePeopleFinders, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-peekyou', createScrapeRoute(scrapePeekyou, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-thatsthem', createScrapeRoute(scrapeThatsThem, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-addresses', createScrapeRoute(scrapeAddresses, ['searchTerm', 'location', 'pages', 'socketId']));
app.post('/scrape-pipl', createScrapeRoute(scrapePipl, ['searchTerm', 'location', 'pages', 'socketId']));


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

// Add input validation for SMS
function validatePhoneNumber(number) {
  try {
    const phoneNumber = parsePhoneNumberFromString(number, 'US');
    return phoneNumber && phoneNumber.isValid();
  } catch {
    return false;
  }
}

app.post('/generate-credentials', verifyAdmin, async (req, res) => {
  try {
    const { username } = req.body;
    const generatedUsername = username || 'user' + crypto.randomBytes(3).toString('hex');
    const generatedPassword = crypto.randomBytes(6).toString('base64').slice(0, 10);
    const passwordHash = await bcrypt.hash(generatedPassword, 12);
    
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 14);

    await mongoDb.collection('users').insertOne({
      username: generatedUsername,
      password_hash: passwordHash,
      rawPassword: generatedPassword, // Store the raw password for admin viewing
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
      expiresAt: expiresAt.toISOString()
    });
  } catch (err) {
    logger.error('Credential Generation Error:', err);
    res.status(500).json({ success: false, error: err.message }); // More detailed error
  }
});

app.get('/get-credentials', verifyAdmin, async (req, res) => {
  try {
    const users = await mongoDb.collection('users')
      .find({ role: 'user' })
      .sort({ created_at: -1 })
      .toArray();
      
    const credentials = users.map(user => ({
      username: user.username,
      password: user.rawPassword, // <- this must exist in DB
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

app.post('/save-extraction', verifyUser, async (req, res) => {
  try {
    const { source, searchTerm, location, results } = req.body;
    
    const extraction = {
      userId: req.user._id,
      source,
      searchTerm,
      location,
      resultsCount: results.length,
      results: results.slice(0, 100), // Store first 100 results
      createdAt: new Date()
    };
    
    await mongoDb.collection('extractions').insertOne(extraction);
    res.json({ success: true });
    
  } catch (err) {
    next(err);
  }
});

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
    logger.error(`CAPTCHA Error: ${err.message}`);
    // Implement fallback strategy
    await page.waitForTimeout(10000);  // Wait before retry
    await page.reload();
    return false;
  }
}

// Add proxy health checking
async function checkProxy(proxy) {
  try {
    const tester = await axios.get('http://example.com', {
      proxy: { host: proxy.split(':')[0], port: proxy.split(':')[1] },
      timeout: 5000
    });
    return true;
  } catch {
    return false;
  }
}

function handleScraperError(err, socketId) {
  logger.error(`Scraper Error: ${err.message}`);
  if (socketId && activeBrowsers[socketId]) {
    io.to(socketId).emit('error', {
      code: err.code || 'SCRAPER_FAILURE',
      message: err.message
    });
  }
}

function getNextProxy() {
  if (proxyList.length === 0) return null;
  
  proxyIndex = (proxyIndex + 1) % proxyList.length;
  return proxyList[proxyIndex];
}

async function getUser(username) {
  return await mongoDb.collection('users').findOne({ username });
}

// Start server
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
server.listen(PORT, HOST, () => {
  logger.info(`Server running on http://${HOST}:${PORT}`);
});