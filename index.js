require('dotenv').config();

const express = require('express');
const fileUpload = require('express-fileupload');
const favicon = require('serve-favicon');
const axios = require('axios');
const path = require('path');
const {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} = require('crypto');
const cfonts = require('cfonts');
const nodemailer = require('nodemailer');
const { rateLimit } = require('express-rate-limit');
const { ObjectId } = require('mongodb');
const { getBucket, getDb } = require('./lib/mongodb');
const {
  createUploadUrl,
  deleteObject,
  getPublicUrl,
  headObject,
  updateObjectExpiration,
} = require('./lib/r2');
const {
  createApiKey,
  hashApiKey,
  hashPassword,
  verifyPassword,
} = require('./lib/accounts');
const {
  createSession,
  destroySession,
  requireAdmin,
  requireUser,
  sessionMiddleware,
} = require('./lib/auth');

const app = express();
const PORT = process.env.PORT || 7001;
const PUBLIC_BASE_URL = new URL(
  process.env.PUBLIC_BASE_URL || 'https://cdn.huskydev.space'
).origin;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'alfredojoseamaya4580@gmail.com').trim().toLowerCase();
const DEFAULT_EXPIRATION = '12h';
const MAX_USER_STORAGE_BYTES = 100 * 1024 * 1024 * 1024;
const MAX_R2_SINGLE_PUT_SIZE = 5 * 1024 * 1024 * 1024;
const MAX_R2_UPLOAD_SIZE = Number.parseInt(process.env.MAX_R2_UPLOAD_SIZE, 10) || MAX_R2_SINGLE_PUT_SIZE;
const R2_STORAGE_LIMIT_BYTES = 9_500_000_000;
const R2_STORAGE_ALERT_BYTES = 9_000_000_000;
const R2_CLASS_A_ALERT = 900_000;
const R2_CLASS_A_BLOCK = 950_000;
const R2_CLASS_B_ALERT = 9_000_000;
const R2_CLASS_B_BLOCK = 9_500_000;
const R2_LARGE_UPLOAD_ALERT_BYTES = 1_000_000_000;
const R2_USAGE_WEBHOOK_SECRET = process.env.R2_USAGE_WEBHOOK_SECRET || '';
const R2_CLASS_A_BASELINE_MONTH = process.env.R2_CLASS_A_BASELINE_MONTH || '';
const R2_CLASS_A_BASELINE_CONFIG = Number(process.env.R2_CLASS_A_BASELINE || 0);
if (!Number.isSafeInteger(R2_CLASS_A_BASELINE_CONFIG) || R2_CLASS_A_BASELINE_CONFIG < 0) {
  throw new Error('R2_CLASS_A_BASELINE must be a non-negative integer.');
}
const R2_CLASS_A_BASELINE = R2_CLASS_A_BASELINE_MONTH === new Date().toISOString().slice(0, 7)
  && Number.isSafeInteger(R2_CLASS_A_BASELINE_CONFIG)
  && R2_CLASS_A_BASELINE_CONFIG > 0
  ? R2_CLASS_A_BASELINE_CONFIG
  : 0;
const R2_UNTRACKED_STORAGE_BYTES = Number(process.env.R2_UNTRACKED_STORAGE_BYTES || 0);
if (!Number.isSafeInteger(R2_UNTRACKED_STORAGE_BYTES) || R2_UNTRACKED_STORAGE_BYTES < 0) {
  throw new Error('R2_UNTRACKED_STORAGE_BYTES must be a non-negative integer.');
}
if (MAX_R2_UPLOAD_SIZE > MAX_R2_SINGLE_PUT_SIZE) {
  throw new Error('MAX_R2_UPLOAD_SIZE cannot exceed the 5 GB single-request R2 upload limit.');
}
const ADMIN_PERMISSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
const ACCOUNT_INDEXES = new WeakMap();
const EXPIRATION_OPTIONS = {
  '30m': { label: '30 minutes', milliseconds: 30 * 60 * 1000 },
  '2h': { label: '2 hours', milliseconds: 2 * 60 * 60 * 1000 },
  '12h': { label: '12 hours', milliseconds: 12 * 60 * 60 * 1000 },
  '2d': { label: '2 days', milliseconds: 2 * 24 * 60 * 60 * 1000 },
  '30d': { label: '30 days', milliseconds: 30 * 24 * 60 * 60 * 1000 },
  '1y': { label: '1 year', milliseconds: 365 * 24 * 60 * 60 * 1000 },
  never: { label: 'Permanent', milliseconds: null },
};

// The multipart API is legacy; browser uploads use MAX_R2_UPLOAD_SIZE instead.
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10) || 4 * 1024 * 1024;

const legacyUploadMiddleware = fileUpload({
  createParentPath: true,
  useTempFiles: false,
  limits: { fileSize: MAX_FILE_SIZE },
  abortOnLimit: true,
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.set('trust proxy', process.env.VERCEL ? 1 : false);
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use(favicon(path.join(__dirname, 'assets', 'img', 'favicon.ico')));
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(sessionMiddleware());

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
});
const uploadRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});
let mailTransporter;

function getMailTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    throw new Error('SMTP_HOST, SMTP_USER, and SMTP_PASS are required to send admin email.');
  }
  if (!mailTransporter) {
    const port = Number(process.env.SMTP_PORT || 587);
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: process.env.SMTP_SECURE === 'true' || port === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
  }
  return mailTransporter;
}

async function sendAdminAlert(subject, text) {
  await getMailTransporter().sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: ADMIN_EMAIL,
    subject,
    text,
  });
}

function isPaidPermissionActive(user) {
  return user.paidUntil instanceof Date && user.paidUntil.getTime() > Date.now();
}

function getPage(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 1;
}

function getAuthReturnPath(value) {
  return value === 'permanent' ? '/?expiresIn=never' : '/account';
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  const referer = req.get('referer');
  try {
    if (origin && new URL(origin).origin !== PUBLIC_BASE_URL) {
      return res.status(403).send('Cross-origin form submission rejected.');
    }
    if (!origin && referer && new URL(referer).origin !== PUBLIC_BASE_URL) {
      return res.status(403).send('Cross-origin form submission rejected.');
    }
    return next();
  } catch (error) {
    return res.status(403).send('Invalid request origin.');
  }
}

async function ensureAccountIndexes(db) {
  if (!ACCOUNT_INDEXES.has(db)) {
    ACCOUNT_INDEXES.set(
      db,
      Promise.all([
        db.collection('users').createIndex({ email: 1 }, { unique: true }),
        db.collection('users').createIndex({ apiKeyHash: 1 }, { sparse: true, unique: true }),
        db.collection('payment_requests').createIndex({ userId: 1, status: 1 }),
        db.collection('admin_login_tokens').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
        db.collection('uploads.files').createIndex({ 'metadata.expiresAt': 1 }),
        db.collection('uploads.files').createIndex({ 'metadata.ownerId': 1, uploadDate: -1 }),
        db.collection('files').createIndex({ filename: 1 }, { unique: true }),
        db.collection('files').createIndex({ intentId: 1 }, { unique: true }),
        db.collection('files').createIndex({ 'metadata.ownerId': 1, uploadDate: -1 }),
        db.collection('files').createIndex({ 'metadata.expiresAt': 1 }),
        db.collection('upload_intents').createIndex({ expiresAt: 1 }),
        db.collection('ip_rate_limits').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
      ])
    );
  }
  await ACCOUNT_INDEXES.get(db);
}

function currentUsageMonth() {
  return new Date().toISOString().slice(0, 7);
}

async function ensureR2Usage(db) {
  const usage = db.collection('r2_usage');
  let state = await usage.findOne({ _id: 'global' });
  if (state) return state;
  if (
    process.env.R2_GATEWAY_URL
    && R2_CLASS_A_BASELINE_MONTH !== currentUsageMonth()
  ) {
    throw new Error('Set R2_CLASS_A_BASELINE_MONTH to the current YYYY-MM month before initializing R2 usage counters.');
  }

  const [storedFiles, pendingIntents] = await Promise.all([
    db.collection('files').aggregate([
      { $group: { _id: null, bytes: { $sum: '$length' } } },
    ]).toArray(),
    db.collection('upload_intents').aggregate([
      {
        $match: {
          status: { $in: ['pending', 'completing'] },
          expiresAt: { $gt: new Date() },
        },
      },
      { $group: { _id: null, bytes: { $sum: '$size' } } },
    ]).toArray(),
  ]);
  try {
    await usage.insertOne({
      _id: 'global',
      month: currentUsageMonth(),
      storageBytes: (storedFiles[0] && storedFiles[0].bytes || 0)
        + (pendingIntents[0] && pendingIntents[0].bytes || 0)
        + R2_UNTRACKED_STORAGE_BYTES,
      classAEstimate: R2_CLASS_A_BASELINE,
      classB: 0,
      alerts: {},
    });
  } catch (error) {
    if (error.code !== 11000) throw error;
  }
  state = await usage.findOne({ _id: 'global' });
  return state;
}

async function getCurrentR2Usage(db) {
  const usage = db.collection('r2_usage');
  await ensureR2Usage(db);
  const month = currentUsageMonth();
  await usage.updateOne(
    { _id: 'global', month: { $ne: month } },
    { $set: { month, classAEstimate: 0, classB: 0, alerts: {} } }
  );
  return usage.findOne({ _id: 'global' });
}

async function sendUsageThresholdAlert(db, key, thresholdReached, subject, text) {
  if (!thresholdReached) return true;
  const usage = db.collection('r2_usage');
  const claimed = await usage.updateOne(
    { _id: 'global', [`alerts.${key}`]: { $ne: true } },
    { $set: { [`alerts.${key}`]: true } }
  );
  if (!claimed.modifiedCount) return true;
  try {
    await sendAdminAlert(subject, text);
    return true;
  } catch (error) {
    await usage.updateOne({ _id: 'global' }, { $unset: { [`alerts.${key}`]: '' } });
    console.error(`Unable to send R2 ${key} alert email:`, error);
    return false;
  }
}

async function alertR2UsageThresholds(db, state) {
  await sendUsageThresholdAlert(
    db,
    'storage90',
    state.storageBytes >= R2_STORAGE_ALERT_BYTES,
    'R2 storage reached 90%',
    `Managed R2 storage reached ${(state.storageBytes / 1e9).toFixed(2)} GB of the 9.5 GB safety limit. New uploads will be blocked at 9.5 GB.`
  );
  await sendUsageThresholdAlert(
    db,
    'classA90',
    state.classAEstimate >= R2_CLASS_A_ALERT,
    'R2 Class A usage reached 90%',
    `Estimated R2 Class A operations reached ${state.classAEstimate.toLocaleString()} of the 950,000 safety limit. New uploads will be blocked at 950,000 estimated operations.`
  );
}

function getR2GatewayUrl(pathname) {
  if (!process.env.R2_GATEWAY_URL) return null;
  if (!R2_USAGE_WEBHOOK_SECRET) {
    throw new Error('R2_USAGE_WEBHOOK_SECRET is required when R2_GATEWAY_URL is configured.');
  }
  const base = new URL(process.env.R2_GATEWAY_URL);
  if (
    base.protocol !== 'https:'
    || base.username
    || base.password
    || base.pathname !== '/'
    || base.search
    || base.hash
  ) {
    throw new Error('R2_GATEWAY_URL must be an HTTPS URL without credentials, query, or fragment.');
  }
  return new URL(pathname, base);
}

async function syncR2ClassBUsage(db) {
  const gatewayUrl = getR2GatewayUrl('/_internal/usage');
  if (!gatewayUrl) return (await getCurrentR2Usage(db)).classB;
  const response = await fetch(gatewayUrl, {
    headers: { Authorization: `Bearer ${R2_USAGE_WEBHOOK_SECRET}` },
  });
  if (!response.ok) throw new Error(`R2 gateway usage query failed with HTTP ${response.status}.`);
  const usage = await response.json();
  if (
    usage.month !== currentUsageMonth()
    || !Number.isSafeInteger(usage.classB)
    || usage.classB < 0
  ) {
    throw new Error('R2 gateway returned an invalid monthly usage counter.');
  }
  await getCurrentR2Usage(db);
  await db.collection('r2_usage').updateOne(
    { _id: 'global', month: usage.month },
    [{ $set: { classB: { $max: [{ $ifNull: ['$classB', 0] }, usage.classB] } } }]
  );
  const state = await db.collection('r2_usage').findOne({ _id: 'global' });
  await sendUsageThresholdAlert(
    db,
    'classB90',
    state.classB >= R2_CLASS_B_ALERT,
    'R2 Class B usage reached 90%',
    `Cloudflare Worker measured ${state.classB.toLocaleString()} R2 Class B operations this month. Operations will be blocked at ${R2_CLASS_B_BLOCK.toLocaleString()}.`
  );
  return state.classB;
}

async function reserveR2ClassBOperation(db) {
  const gatewayUrl = getR2GatewayUrl('/_internal/charge-class-b');
  if (gatewayUrl) {
    const response = await fetch(gatewayUrl, {
      method: 'POST',
      headers: { Authorization: `Bearer ${R2_USAGE_WEBHOOK_SECRET}` },
    });
    if (response.status === 429) return false;
    if (!response.ok) throw new Error(`R2 gateway operation reservation failed with HTTP ${response.status}.`);
    const result = await response.json();
    if (result.allowed !== true) return false;
    await syncR2ClassBUsage(db);
    return true;
  }

  const state = await getCurrentR2Usage(db);
  const update = await db.collection('r2_usage').updateOne(
    {
      _id: 'global',
      month: state.month,
      classB: { $lt: R2_CLASS_B_BLOCK },
    },
    { $inc: { classB: 1 } }
  );
  const updated = await db.collection('r2_usage').findOne({ _id: 'global' });
  await sendUsageThresholdAlert(
    db,
    'classB90',
    updated.classB >= R2_CLASS_B_ALERT,
    'R2 Class B usage reached 90%',
    `Tracked R2 Class B operations reached ${updated.classB.toLocaleString()} of the ${R2_CLASS_B_BLOCK.toLocaleString()} safety limit.`
  );
  return update.modifiedCount === 1;
}

async function reserveR2Upload(db, size) {
  await syncR2ClassBUsage(db);
  let state = await getCurrentR2Usage(db);
  const usage = db.collection('r2_usage');
  const month = state.month;
  const result = await usage.updateOne(
    {
      _id: 'global',
      month,
      storageBytes: {
        $lt: R2_STORAGE_LIMIT_BYTES,
        $lte: R2_STORAGE_LIMIT_BYTES - size,
      },
      classAEstimate: { $lt: R2_CLASS_A_BLOCK },
      classB: { $lt: R2_CLASS_B_BLOCK },
    },
    { $inc: { storageBytes: size, classAEstimate: 1 } }
  );
  if (!result.modifiedCount) {
    state = await getCurrentR2Usage(db);
    await alertR2UsageThresholds(db, state);
    if (
      state.storageBytes >= R2_STORAGE_LIMIT_BYTES
      || state.storageBytes + size > R2_STORAGE_LIMIT_BYTES
    ) {
      return { ok: false, reason: 'storage' };
    }
    if (state.classAEstimate >= R2_CLASS_A_BLOCK) {
      return { ok: false, reason: 'classA' };
    }
    if (state.classB >= R2_CLASS_B_BLOCK) {
      return { ok: false, reason: 'classB' };
    }
    return { ok: false, reason: 'usage' };
  }

  state = await usage.findOne({ _id: 'global' });
  await alertR2UsageThresholds(db, state);
  return { ok: true, state };
}

async function releaseR2Storage(db, bytes) {
  await db.collection('r2_usage').updateOne(
    { _id: 'global' },
    [{
      $set: {
        storageBytes: {
          $max: [0, { $subtract: [{ $ifNull: ['$storageBytes', 0] }, bytes] }],
        },
      },
    }]
  );
}

async function releaseR2UploadReservation(db, bytes) {
  await db.collection('r2_usage').updateOne(
    { _id: 'global' },
    [{
      $set: {
        storageBytes: {
          $max: [0, { $subtract: [{ $ifNull: ['$storageBytes', 0] }, bytes] }],
        },
        classAEstimate: {
          $max: [0, { $subtract: [{ $ifNull: ['$classAEstimate', 0] }, 1] }],
        },
      },
    }]
  );
}

async function trackR2ClassAOperation(db) {
  const state = await getCurrentR2Usage(db);
  await db.collection('r2_usage').updateOne(
    { _id: 'global', month: state.month },
    { $inc: { classAEstimate: 1 } }
  );
  const updated = await db.collection('r2_usage').findOne({ _id: 'global' });
  await alertR2UsageThresholds(db, updated);
}

async function enforceUploadIpLimits(req, res, next) {
  try {
    const db = await getDb();
    await ensureAccountIndexes(db);
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const ipHash = createHash('sha256')
      .update(`${process.env.SESSION_SECRET}:${ip}`)
      .digest('hex');
    const now = Date.now();
    const limits = [
      { duration: 15 * 60 * 1000, maximum: 20 },
      { duration: 24 * 60 * 60 * 1000, maximum: 100 },
    ];
    for (const limit of limits) {
      const start = Math.floor(now / limit.duration) * limit.duration;
      const counter = await db.collection('ip_rate_limits').findOneAndUpdate(
        { _id: `${ipHash}:${limit.duration}:${start}` },
        {
          $inc: { count: 1 },
          $setOnInsert: { expiresAt: new Date(start + limit.duration * 2) },
        },
        { upsert: true, returnDocument: 'after' }
      );
      const current = counter && (counter.value || counter);
      if (!current || !Number.isSafeInteger(current.count)) {
        throw new Error('Unable to read persistent upload rate limit counter.');
      }
      if (current.count > limit.maximum) {
        return res.status(429).json({
          status: false,
          message: 'Too many upload requests from this IP. Please try again later.',
        });
      }
    }
    return next();
  } catch (error) {
    return next(error);
  }
}

app.get('/', (req, res) => {
  res.render('home.ejs', {
    expirationOptions: EXPIRATION_OPTIONS,
    user: req.auth && req.auth.role === 'user' ? req.auth.user : null,
    canUploadPermanent: Boolean(req.auth && req.auth.role === 'user' && isPaidPermissionActive(req.auth.user)),
    selectedExpiration: req.query.expiresIn === 'never' ? 'never' : DEFAULT_EXPIRATION,
  });
});

app.get('/docs', (req, res) => {
  res.render('docs.ejs');
});

app.get('/register', (req, res) => {
  res.render('register.ejs', {
    error: null,
    next: req.query.next === 'permanent' ? 'permanent' : '',
  });
});

app.post('/register', requireSameOrigin, authRateLimit, async (req, res, next) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const next = req.body.next === 'permanent' ? 'permanent' : '';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return res.status(400).render('register.ejs', { error: 'Enter a valid email address.', next });
    }
    if (password.length < 12 || password.length > 128) {
      return res.status(400).render('register.ejs', { error: 'Password must be 12-128 characters.', next });
    }

    const db = await getDb();
    await ensureAccountIndexes(db);
    const users = db.collection('users');
    if (await users.findOne({ email })) {
      return res.status(409).render('register.ejs', {
        error: 'An account with that email already exists.',
        next,
      });
    }
    const user = {
      email,
      passwordHash: await hashPassword(password),
      storageBytes: 0,
      paidUntil: null,
      disabled: false,
      createdAt: new Date(),
    };
    const result = await users.insertOne(user);
    await createSession(res, { role: 'user', userId: result.insertedId.toString() });
    return res.redirect(getAuthReturnPath(next));
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).render('register.ejs', {
        error: 'An account with that email already exists.',
        next: req.body.next === 'permanent' ? 'permanent' : '',
      });
    }
    return next(error);
  }
});

app.get('/login', (req, res) => {
  res.render('login.ejs', {
    error: null,
    next: req.query.next === 'permanent' ? 'permanent' : '',
  });
});

app.post('/login', requireSameOrigin, authRateLimit, async (req, res, next) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const next = req.body.next === 'permanent' ? 'permanent' : '';
    const db = await getDb();
    await ensureAccountIndexes(db);
    const user = await db.collection('users').findOne({ email, disabled: { $ne: true } });
    if (!user || !(await verifyPassword(password, user.passwordHash))) {
      return res.status(401).render('login.ejs', { error: 'Invalid email or password.', next });
    }

    await createSession(res, { role: 'user', userId: user._id.toString() });
    return res.redirect(getAuthReturnPath(next));
  } catch (error) {
    return next(error);
  }
});

app.post('/logout', requireSameOrigin, async (req, res, next) => {
  try {
    await destroySession(req, res);
    return res.redirect('/');
  } catch (error) {
    return next(error);
  }
});

async function renderAccount(res, user, options = {}) {
  const db = await getDb();
  const page = getPage(options.page);
  const pageSize = 50;
  const [{ files, total: fileCount }, paymentRequest] = await Promise.all([
    getManagedFiles(db, { ownerId: user._id, page, pageSize }),
    db.collection('payment_requests').findOne(
      { userId: user._id, status: 'pending' },
      { sort: { createdAt: -1 } }
    ),
  ]);
  return res.render('account.ejs', {
    user,
    files,
    filePage: page,
    filePages: Math.max(1, Math.ceil(fileCount / pageSize)),
    paymentRequest,
    canUploadPermanent: isPaidPermissionActive(user),
    error: options.error || null,
    newApiKey: options.newApiKey || null,
    paymentRequested: options.paymentRequested || false,
    paymentInstructions: process.env.PAYMENT_INSTRUCTIONS || null,
  });
}

app.get('/account', requireUser, async (req, res, next) => {
  try {
    return await renderAccount(res, req.auth.user, {
      paymentRequested: req.query.payment === 'requested',
      error: req.query.quota === 'exceeded'
        ? 'The account 100 GB storage limit has been reached.'
        : req.query.payment === 'required'
          ? 'Permanent storage requires an active permission.'
          : null,
      page: req.query.filesPage,
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/account/request-permanent', requireSameOrigin, requireUser, async (req, res, next) => {
  try {
    if (isPaidPermissionActive(req.auth.user)) return res.redirect('/account');
    const db = await getDb();
    const requests = db.collection('payment_requests');
    const existing = await requests.findOne({ userId: req.auth.user._id, status: 'pending' });
    if (!existing) {
      await requests.insertOne({
        userId: req.auth.user._id,
        email: req.auth.user.email,
        amountCents: 500,
        currency: 'USD',
        status: 'pending',
        createdAt: new Date(),
      });
    }
    return res.redirect('/account?payment=requested');
  } catch (error) {
    return next(error);
  }
});

app.post('/account/api-key', requireSameOrigin, requireUser, authRateLimit, async (req, res, next) => {
  try {
    const db = await getDb();
    await ensureAccountIndexes(db);
    const apiKey = createApiKey();
    await db.collection('users').updateOne(
      { _id: req.auth.user._id },
      { $set: { apiKeyHash: apiKey.hash, apiKeyPrefix: apiKey.prefix, apiKeyCreatedAt: new Date() } }
    );
    return await renderAccount(res, {
      ...req.auth.user,
      apiKeyPrefix: apiKey.prefix,
      apiKeyCreatedAt: new Date(),
    }, { newApiKey: apiKey.key });
  } catch (error) {
    return next(error);
  }
});

app.post('/account/api-key/revoke', requireSameOrigin, requireUser, async (req, res, next) => {
  try {
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: req.auth.user._id },
      { $unset: { apiKeyHash: '', apiKeyPrefix: '', apiKeyCreatedAt: '' } }
    );
    return res.redirect('/account');
  } catch (error) {
    return next(error);
  }
});

app.post('/account/files/:id/delete', requireSameOrigin, requireUser, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid file ID.');
    const db = await getDb();
    const file = await db.collection('files').findOne({
      _id: new ObjectId(req.params.id),
      'metadata.ownerId': req.auth.user._id,
    }) || await (await getBucket()).find({
      _id: new ObjectId(req.params.id),
      'metadata.ownerId': req.auth.user._id,
    }).limit(1).next();
    if (!file) return res.status(404).send('File not found.');
    await deleteStoredFile(file);
    return res.redirect('/account');
  } catch (error) {
    return next(error);
  }
});

app.get('/admin/login', (req, res) => {
  res.render('admin-login.ejs', { error: null, sent: false, token: null });
});

app.post('/admin/login', requireSameOrigin, authRateLimit, async (req, res, next) => {
  try {
    const adminEmail = ADMIN_EMAIL;
    const submittedEmail = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      return res.status(503).render('admin-login.ejs', {
        error: 'Admin email and SMTP environment variables are not configured.',
        sent: false,
        token: null,
      });
    }

    if (submittedEmail === adminEmail) {
      const db = await getDb();
      await ensureAccountIndexes(db);
      const token = randomBytes(32).toString('hex');
      const tokenHash = createHash('sha256').update(token).digest('hex');
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
      await db.collection('admin_login_tokens').insertOne({
        tokenHash,
        email: adminEmail,
        createdAt: new Date(),
        expiresAt,
      });

      const verificationUrl = `${PUBLIC_BASE_URL}/admin/verify?token=${token}`;
      await getMailTransporter().sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: adminEmail,
        subject: 'Husky_dev CDN admin sign-in',
        text: `Use this one-time link to sign in to the admin panel. It expires in 15 minutes:\n\n${verificationUrl}`,
      });
    }

    return res.render('admin-login.ejs', {
      error: null,
      sent: true,
      token: null,
    });
  } catch (error) {
    return next(error);
  }
});

app.get('/admin/verify', async (req, res, next) => {
  try {
    const token = typeof req.query.token === 'string' ? req.query.token : '';
    const validToken = /^[a-f0-9]{64}$/.test(token) ? token : '';
    return res.render('admin-login.ejs', {
      error: null,
      sent: false,
      token: validToken,
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/verify', requireSameOrigin, authRateLimit, async (req, res, next) => {
  try {
    const token = typeof req.body.token === 'string' ? req.body.token : '';
    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(400).render('admin-login.ejs', {
        error: 'Invalid or expired sign-in link.',
        sent: false,
        token: null,
      });
    }
    const db = await getDb();
    const result = await db.collection('admin_login_tokens').findOneAndDelete({
      tokenHash: createHash('sha256').update(token).digest('hex'),
      expiresAt: { $gt: new Date() },
    });
    const loginToken = result && (result.value || result);
    if (!loginToken || loginToken.email !== ADMIN_EMAIL) {
      return res.status(400).render('admin-login.ejs', {
        error: 'Invalid or expired sign-in link.',
        sent: false,
        token: null,
      });
    }
    await createSession(res, { role: 'admin', email: loginToken.email });
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.get('/admin', requireAdmin, async (req, res, next) => {
  try {
    const db = await getDb();
    await ensureAccountIndexes(db);
    const pageSize = 50;
    const accountsPage = getPage(req.query.accountsPage);
    const requestsPage = getPage(req.query.requestsPage);
    const filesPage = getPage(req.query.filesPage);
    const [users, userCount, requests, requestCount, filePage] = await Promise.all([
      db.collection('users').find({}).sort({ createdAt: -1 }).skip((accountsPage - 1) * pageSize).limit(pageSize).toArray(),
      db.collection('users').countDocuments({}),
      db.collection('payment_requests').find({ status: 'pending' }).sort({ createdAt: 1 }).skip((requestsPage - 1) * pageSize).limit(pageSize).toArray(),
      db.collection('payment_requests').countDocuments({ status: 'pending' }),
      getManagedFiles(db, { page: filesPage, pageSize }),
    ]);
    const { files, total: fileCount } = filePage;
    await syncR2ClassBUsage(db);
    const r2Usage = await getCurrentR2Usage(db);
    const ownerIds = [...new Set(files
      .map((file) => file.metadata && file.metadata.ownerId)
      .filter(Boolean)
      .map((id) => id.toString()))];
    const owners = ownerIds.length
      ? await db.collection('users').find({ _id: { $in: ownerIds.map((id) => new ObjectId(id)) } }).toArray()
      : [];
    const ownerById = new Map(owners.map((user) => [user._id.toString(), user]));
    return res.render('admin.ejs', {
      adminEmail: req.auth.email,
      users,
      requests,
      files,
      accountsPage,
      accountsPages: Math.max(1, Math.ceil(userCount / pageSize)),
      requestsPage,
      requestsPages: Math.max(1, Math.ceil(requestCount / pageSize)),
      filesPage,
      filesPages: Math.max(1, Math.ceil(fileCount / pageSize)),
      ownerById,
      r2Usage,
      r2StorageLimitBytes: R2_STORAGE_LIMIT_BYTES,
      r2ClassALimit: R2_CLASS_A_BLOCK,
      r2ClassBLimit: R2_CLASS_B_BLOCK,
      expirationOptions: EXPIRATION_OPTIONS,
      formatFileSize,
      now: new Date(),
    });
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/payment-requests/:id/approve', requireSameOrigin, requireAdmin, async (req, res, next) => {
  if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid payment request ID.');
  const requestId = new ObjectId(req.params.id);
  let claimed = false;
  let permissionGranted = false;
  try {
    const db = await getDb();
    const claim = await db.collection('payment_requests').updateOne(
      { _id: requestId, status: 'pending' },
      { $set: { status: 'processing', reviewedBy: req.auth.email } }
    );
    if (claim.matchedCount !== 1) return res.status(404).send('Pending payment request not found.');
    claimed = true;
    const request = await db.collection('payment_requests').findOne({ _id: requestId });
    if (!request) throw new Error('Claimed payment request disappeared.');
    const user = await db.collection('users').findOne({ _id: request.userId, disabled: { $ne: true } });
    if (!user) {
      await db.collection('payment_requests').updateOne(
        { _id: requestId, status: 'processing' },
        { $set: { status: 'rejected', reviewedAt: new Date() } }
      );
      return res.status(404).send('Account not found or disabled.');
    }
    const startsAt = isPaidPermissionActive(user) ? user.paidUntil : new Date();
    const paidUntil = new Date(startsAt.getTime() + ADMIN_PERMISSION_DURATION_MS);
    const grant = await db.collection('users').updateOne(
      { _id: user._id },
      { $set: { paidUntil, permissionUpdatedAt: new Date() } }
    );
    if (grant.matchedCount !== 1) throw new Error('Unable to grant permanent-storage permission.');
    permissionGranted = true;
    await db.collection('payment_requests').updateOne(
      { _id: requestId, status: 'processing' },
      { $set: { status: 'approved', reviewedAt: new Date(), paidUntil } }
    );
    return res.redirect('/admin');
  } catch (error) {
    if (claimed && !permissionGranted) {
      try {
        const db = await getDb();
        await db.collection('payment_requests').updateOne(
          { _id: requestId, status: 'processing' },
          { $set: { status: 'pending' }, $unset: { reviewedBy: '' } }
        );
      } catch (rollbackError) {
        console.error('Unable to release payment request after approval failure:', rollbackError);
      }
    }
    return next(error);
  }
});

app.post('/admin/payment-requests/:id/reject', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid payment request ID.');
    const db = await getDb();
    await db.collection('payment_requests').updateOne(
      { _id: new ObjectId(req.params.id), status: 'pending' },
      { $set: { status: 'rejected', reviewedAt: new Date(), reviewedBy: req.auth.email } }
    );
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/users/:id/grant', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid account ID.');
    const db = await getDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.params.id), disabled: { $ne: true } });
    if (!user) return res.status(404).send('Account not found or disabled.');
    const startsAt = isPaidPermissionActive(user) ? user.paidUntil : new Date();
    await db.collection('users').updateOne(
      { _id: user._id },
      { $set: { paidUntil: new Date(startsAt.getTime() + ADMIN_PERMISSION_DURATION_MS), permissionUpdatedAt: new Date() } }
    );
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/users/:id/revoke', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid account ID.');
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { paidUntil: new Date(), permissionUpdatedAt: new Date() } }
    );
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/users/:id/toggle-disabled', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid account ID.');
    const db = await getDb();
    const users = db.collection('users');
    const user = await users.findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.status(404).send('Account not found.');
    await users.updateOne(
      { _id: user._id },
      { $set: { disabled: !user.disabled, disabledAt: user.disabled ? null : new Date() } }
    );
    if (!user.disabled) {
      await db.collection('sessions').deleteMany({ role: 'user', userId: user._id.toString() });
    }
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/users/:id/api-key/revoke', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid account ID.');
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $unset: { apiKeyHash: '', apiKeyPrefix: '', apiKeyCreatedAt: '' } }
    );
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/files/:id/delete', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid file ID.');
    const db = await getDb();
    const file = await db.collection('files').findOne({ _id: new ObjectId(req.params.id) })
      || await (await getBucket()).find({ _id: new ObjectId(req.params.id) }).limit(1).next();
    if (!file) return res.status(404).send('File not found.');
    await deleteStoredFile(file);
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

app.post('/admin/files/:id/expiration', requireSameOrigin, requireAdmin, async (req, res, next) => {
  try {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).send('Invalid file ID.');
    const lifetime = req.body && req.body.expiresIn;
    if (
      typeof lifetime !== 'string'
      || !Object.prototype.hasOwnProperty.call(EXPIRATION_OPTIONS, lifetime)
    ) {
      return res.status(400).send('Choose a valid file lifetime.');
    }
    const expiration = getExpiration(lifetime);
    if (!expiration) return res.status(400).send('Invalid file lifetime.');
    const db = await getDb();
    const id = new ObjectId(req.params.id);
    const collection = db.collection('files');
    let file = await collection.findOne({ _id: id });
    let target = collection;
    if (!file) {
      target = db.collection('uploads.files');
      file = await target.findOne({ _id: id });
    }
    if (!file) return res.status(404).send('File not found.');
    if (file.key) {
      const state = await getCurrentR2Usage(db);
      if (state.classAEstimate >= R2_CLASS_A_BLOCK || state.classB >= R2_CLASS_B_BLOCK) {
        return res.status(429).send('R2 object changes are paused at the monthly operation safety limit.');
      }
      const reserved = await db.collection('r2_usage').updateOne(
        {
          _id: 'global',
          month: state.month,
          classAEstimate: { $lt: R2_CLASS_A_BLOCK },
          classB: { $lt: R2_CLASS_B_BLOCK },
        },
        { $inc: { classAEstimate: 1 } }
      );
      if (!reserved.modifiedCount) {
        return res.status(429).send('R2 object changes are paused at the monthly operation safety limit.');
      }
      let objectUpdated = false;
      try {
        await updateObjectExpiration(file.key, file.contentType, expiration.expiresAt);
        objectUpdated = true;
        const updated = await target.updateOne(
          { _id: id },
          { $set: { 'metadata.expiresAt': expiration.expiresAt } }
        );
        if (updated.matchedCount !== 1) throw new Error('File metadata changed while updating its lifetime.');
        await alertR2UsageThresholds(db, await db.collection('r2_usage').findOne({ _id: 'global' }));
        return res.redirect('/admin');
      } catch (error) {
        if (objectUpdated) {
          try {
            await updateObjectExpiration(
              file.key,
              file.contentType,
              file.metadata && file.metadata.expiresAt
            );
            await trackR2ClassAOperation(db);
          } catch (rollbackError) {
            console.error('Unable to roll back R2 expiration metadata:', rollbackError);
          }
        }
        throw error;
      }
    }
    const updated = await target.updateOne(
      { _id: id },
      { $set: { 'metadata.expiresAt': expiration.expiresAt } }
    );
    if (updated.matchedCount !== 1) return res.status(404).send('File not found.');
    return res.redirect('/admin');
  } catch (error) {
    return next(error);
  }
});

// ---------- Helpers ----------

function generateRandomFileName(length) {
  const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

function formatFileSize(size) {
  if (size > 1000000) return `${(size / 1000000).toFixed(2)} MB`;
  if (size > 1000) return `${(size / 1000).toFixed(2)} KB`;
  return `${size} Bytes`;
}

function getExpiration(value) {
  const option = value === undefined || value === '' ? DEFAULT_EXPIRATION : value;
  if (typeof option !== 'string' || !Object.prototype.hasOwnProperty.call(EXPIRATION_OPTIONS, option)) {
    return null;
  }

  const milliseconds = EXPIRATION_OPTIONS[option].milliseconds;
  return {
    option,
    expiresAt: milliseconds === null ? null : new Date(Date.now() + milliseconds),
  };
}

async function findFileDoc(bucket, filename) {
  const docs = await bucket.find({ filename }).toArray();
  return docs[0] || null;
}

async function findStoredFile(db, filename) {
  const file = await db.collection('files').findOne({ filename });
  if (file) return file;
  return findFileDoc(await getBucket(), filename);
}

async function getManagedFiles(db, { ownerId, page, pageSize }) {
  const skip = (page - 1) * pageSize;
  const ownerFilter = ownerId ? { 'metadata.ownerId': ownerId } : {};
  const [result] = await db.collection('files').aggregate([
    { $match: ownerFilter },
    {
      $unionWith: {
        coll: 'uploads.files',
        pipeline: [{ $match: ownerFilter }],
      },
    },
    { $sort: { uploadDate: -1, _id: 1 } },
    {
      $facet: {
        files: [{ $skip: skip }, { $limit: pageSize }],
        total: [{ $count: 'count' }],
      },
    },
  ]).toArray();
  return {
    files: result ? result.files.map((file) => ({
      ...file,
      downloadUrl: file.key ? getPublicUrl(file.key) : null,
    })) : [],
    total: result && result.total.length ? result.total[0].count : 0,
  };
}

function isExpired(doc) {
  const expiresAt = doc.metadata && doc.metadata.expiresAt;
  return expiresAt instanceof Date && expiresAt.getTime() <= Date.now();
}

async function reserveUserStorage(user, bytes) {
  const db = await getDb();
  const result = await db.collection('users').updateOne(
    {
      _id: user._id,
      disabled: { $ne: true },
      $expr: {
        $lte: [
          { $add: [{ $ifNull: ['$storageBytes', 0] }, bytes] },
          MAX_USER_STORAGE_BYTES,
        ],
      },
    },
    { $inc: { storageBytes: bytes } }
  );
  return result.matchedCount === 1;
}

async function releaseUserStorage(userId, bytes) {
  if (!ObjectId.isValid(userId)) return;
  const db = await getDb();
  await db.collection('users').updateOne(
    { _id: new ObjectId(userId) },
    [{
      $set: {
        storageBytes: {
          $max: [0, { $subtract: [{ $ifNull: ['$storageBytes', 0] }, bytes] }],
        },
      },
    }]
  );
}

async function deleteGridFSFile(bucket, file) {
  await bucket.delete(file._id);
  const ownerId = file.metadata && file.metadata.ownerId;
  if (ownerId) await releaseUserStorage(ownerId, file.length);
}

async function deleteStoredFile(file) {
  if (!file.key) {
    return deleteGridFSFile(await getBucket(), file);
  }

  const db = await getDb();
  await trackR2ClassAOperation(db);
  await deleteObject(file.key);
  const result = await db.collection('files').deleteOne({ _id: file._id, key: file.key });
  const ownerId = file.metadata && file.metadata.ownerId;
  if (result.deletedCount) await releaseR2Storage(db, file.length);
  if (result.deletedCount && ownerId) await releaseUserStorage(ownerId, file.length);
}

async function saveUserFile(bucket, filename, buffer, contentType, expiresAt, user) {
  if (!user) {
    await saveToGridFS(bucket, filename, buffer, contentType, expiresAt, null);
    return;
  }

  if (!(await reserveUserStorage(user, buffer.length))) {
    const error = new Error('The account storage limit has been reached.');
    error.code = 'STORAGE_QUOTA_EXCEEDED';
    throw error;
  }

  try {
    await saveToGridFS(bucket, filename, buffer, contentType, expiresAt, user._id);
  } catch (error) {
    await releaseUserStorage(user._id, buffer.length);
    throw error;
  }
}

async function resolveApiKey(req) {
  const authorization = req.get('authorization');
  if (!authorization) return { provided: false, user: null };
  const match = /^Bearer (hdev_[A-Za-z0-9_-]{43})$/.exec(authorization);
  if (!match) return { provided: true, user: null };

  const db = await getDb();
  await ensureAccountIndexes(db);
  const keyHash = hashApiKey(match[1]);
  const user = await db.collection('users').findOne({
    apiKeyHash: keyHash,
    disabled: { $ne: true },
  });
  return { provided: true, user };
}

async function resolveUploadIdentity(req) {
  const apiAuth = await resolveApiKey(req);
  if (apiAuth.provided && !apiAuth.user) {
    return { error: { status: 401, message: 'Invalid API key.' } };
  }

  const sessionUser = req.auth && req.auth.role === 'user' ? req.auth.user : null;
  if (
    apiAuth.user
    && sessionUser
    && apiAuth.user._id.toString() !== sessionUser._id.toString()
  ) {
    return { error: { status: 403, message: 'The session and API key belong to different accounts.' } };
  }
  return { user: apiAuth.user || sessionUser || null };
}

function sanitizeUploadFilename(value) {
  if (typeof value !== 'string' || value.length > 255) return null;
  const basename = path.basename(value.replace(/\\/g, '/')).trim();
  const filename = basename
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .slice(0, 255);
  const truncatedFilename = Array.from(filename).slice(0, 180).join('');
  return truncatedFilename && truncatedFilename !== '.' && truncatedFilename !== '..'
    ? truncatedFilename
    : null;
}

function isValidUploadContentType(value) {
  return typeof value === 'string'
    && value.length <= 127
    && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(value);
}

async function cleanupExpiredUploadIntents(limit = 100) {
  const db = await getDb();
  const intentsCollection = db.collection('upload_intents');
  const now = new Date();
  const intents = await intentsCollection
    .find({
      expiresAt: { $lte: now },
      $or: [
        { status: 'pending' },
        { status: 'cleaning', cleanupLeaseUntil: { $lte: now } },
      ],
    })
    .limit(limit)
    .toArray();

  let cleaned = 0;
  for (const intent of intents) {
    const lease = new Date(Date.now() + 5 * 60 * 1000);
    const claimed = await intentsCollection.updateOne(
      {
        _id: intent._id,
        expiresAt: { $lte: new Date() },
        $or: [
          { status: 'pending' },
          { status: 'cleaning', cleanupLeaseUntil: { $lte: new Date() } },
        ],
      },
      { $set: { status: 'cleaning', cleanupLeaseUntil: lease, updatedAt: new Date() } }
    );
    if (claimed.modifiedCount !== 1) continue;
    await trackR2ClassAOperation(db);
    await deleteObject(intent.key);
    await releaseR2Storage(db, intent.size);
    if (intent.ownerId) {
      const release = await intentsCollection.updateOne(
        { _id: intent._id, status: 'cleaning', quotaReleased: { $ne: true } },
        { $set: { quotaReleased: true } }
      );
      if (release.modifiedCount === 1) await releaseUserStorage(intent.ownerId, intent.size);
    }
    await intentsCollection.updateOne(
      { _id: intent._id, status: 'cleaning' },
      { $set: { status: 'expired', updatedAt: new Date() }, $unset: { cleanupLeaseUntil: '' } }
    );
    cleaned += 1;
  }
  return cleaned;
}

async function deleteExpiredFiles(bucket, limit = 100) {
  const db = await getDb();
  const [expiredR2Files, expiredLegacyFiles] = await Promise.all([
    db.collection('files')
      .find({ 'metadata.expiresAt': { $lte: new Date() } })
      .limit(limit)
      .toArray(),
    bucket
    .find({ 'metadata.expiresAt': { $lte: new Date() } })
    .limit(limit)
    .toArray(),
  ]);

  for (const file of expiredR2Files) {
    await deleteStoredFile(file);
  }
  for (const file of expiredLegacyFiles) {
    await deleteGridFSFile(bucket, file);
  }
  return expiredR2Files.length + expiredLegacyFiles.length;
}

async function uniqueName(bucket, filename) {
  const parsed = path.parse(filename);
  let name = filename;
  let number = 0;
  while (await findFileDoc(bucket, name)) {
    number += 1;
    name = `${parsed.name}-${number}${parsed.ext}`;
  }
  return name;
}

function saveToGridFS(bucket, filename, buffer, contentType, expiresAt, ownerId) {
  return new Promise((resolve, reject) => {
    const metadata = {
      expiresAt: expiresAt || null,
      ...(ownerId ? { ownerId } : {}),
    };
    const uploadStream = bucket.openUploadStream(filename, { contentType, metadata });
    uploadStream.on('error', reject);
    uploadStream.on('finish', () => resolve(uploadStream));
    uploadStream.end(buffer);
  });
}

// ---------- Direct browser uploads to Cloudflare R2 ----------

app.post('/api/presign', requireSameOrigin, uploadRateLimit, enforceUploadIpLimits, async (req, res, next) => {
  let reservedUserId = null;
  let reservedSize = 0;
 let reservedR2Size = 0;
 let r2ReservationHeld = false;
 let intentId = null;
  try {
    const filename = sanitizeUploadFilename(req.body && req.body.filename);
    const contentType = req.body && req.body.contentType;
    const size = req.body && req.body.size;
    const expiration = getExpiration(req.body && req.body.expiresIn);
    if (!filename || !isValidUploadContentType(contentType)) {
      return res.status(400).json({ status: false, message: 'A valid filename and content type are required.' });
    }
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_R2_UPLOAD_SIZE || size > MAX_R2_SINGLE_PUT_SIZE) {
      return res.status(413).json({
        status: false,
        message: `File size must be between 0 bytes and ${formatFileSize(MAX_R2_UPLOAD_SIZE)}.`,
      });
    }
    if (!expiration) {
      return res.status(400).json({ status: false, message: 'Invalid expiration option.' });
    }

    const identity = await resolveUploadIdentity(req);
    if (identity.error) return res.status(identity.error.status).json({ status: false, message: identity.error.message });
    const user = identity.user;
    if (expiration.option === 'never' && !user) {
      return res.status(401).json({ status: false, message: 'Sign in to upload a permanent file.' });
    }
    if (expiration.option === 'never' && !isPaidPermissionActive(user)) {
      return res.status(403).json({ status: false, message: 'Permanent storage permission is not active.' });
    }

    if (user && !(await reserveUserStorage(user, size))) {
      return res.status(413).json({ status: false, message: 'The account storage limit has been reached.' });
    }
    if (user) {
      reservedUserId = user._id;
      reservedSize = size;
    }

    const db = await getDb();
    await ensureAccountIndexes(db);
    await cleanupExpiredUploadIntents();
    const reservation = await reserveR2Upload(db, size);
    if (!reservation.ok) {
      if (reservedUserId) {
        await releaseUserStorage(reservedUserId, reservedSize);
        reservedUserId = null;
      }
      const message = reservation.reason === 'storage'
        ? 'Uploads are paused because the R2 storage safety limit has been reached.'
        : 'Uploads are paused because a monthly R2 operation safety limit has been reached.';
      return res.status(429).json({ status: false, message });
    }
    reservedR2Size = size;
    r2ReservationHeld = true;
    if (size > R2_LARGE_UPLOAD_ALERT_BYTES) {
      await sendAdminAlert(
        'Large R2 upload requested',
        `A ${formatFileSize(size)} file named "${filename}" was requested from IP ${req.ip}. The per-file safety alert threshold is 1 GB.`
      );
    }
    const uploadId = randomUUID();
    const key = `uploads/${uploadId}/${filename}`;
    const storedFilename = `${uploadId.slice(0, 8)}-${filename}`;
    const publicUrl = getPublicUrl(key);
    const uploadUrl = await createUploadUrl(key, contentType, size, expiration.expiresAt);
    const now = new Date();
    const intent = {
      key,
      filename: storedFilename,
      originalFilename: filename,
      publicUrl,
      contentType,
      size,
      expiresIn: expiration.option,
      ownerId: user ? user._id : null,
      status: 'pending',
      createdAt: now,
      expiresAt: new Date(now.getTime() + 15 * 60 * 1000),
    };
    const result = await db.collection('upload_intents').insertOne(intent);
    intentId = result.insertedId;

    return res.json({
      status: true,
      data: {
        intentId: intentId.toString(),
        uploadUrl,
        uploadHeaders: {
          'Content-Type': contentType,
          'If-None-Match': '*',
          ...(expiration.expiresAt
            ? { 'x-amz-meta-cdn-expires-at': expiration.expiresAt.toISOString() }
            : {}),
        },
        key,
        filename,
        publicUrl,
      },
    });
  } catch (error) {
    if (intentId) {
      try {
        const db = await getDb();
        await db.collection('upload_intents').deleteOne({ _id: intentId, status: 'pending' });
      } catch (cleanupError) {
        console.error('Unable to remove failed upload intent:', cleanupError);
      }
    }
    if (reservedUserId) {
      try {
        await releaseUserStorage(reservedUserId, reservedSize);
      } catch (cleanupError) {
        console.error('Unable to release quota after presign failure:', cleanupError);
      }
    }
    if (r2ReservationHeld) {
      try {
        const db = await getDb();
        await releaseR2UploadReservation(db, reservedR2Size);
      } catch (cleanupError) {
        console.error('Unable to release R2 storage reservation after presign failure:', cleanupError);
      }
    }
    return next(error);
  }
});

app.post('/api/files', requireSameOrigin, uploadRateLimit, async (req, res, next) => {
  try {
    const intentId = typeof req.body?.intentId === 'string' && ObjectId.isValid(req.body.intentId)
      ? new ObjectId(req.body.intentId)
      : null;
    if (!intentId) return res.status(400).json({ status: false, message: 'Invalid upload intent.' });

    const identity = await resolveUploadIdentity(req);
    if (identity.error) return res.status(identity.error.status).json({ status: false, message: identity.error.message });
    const db = await getDb();
    const intents = db.collection('upload_intents');
    const intent = await intents.findOne({ _id: intentId });
    if (!intent) return res.status(404).json({ status: false, message: 'Upload intent not found or expired.' });

    if (intent.ownerId && (!identity.user || intent.ownerId.toString() !== identity.user._id.toString())) {
      return res.status(403).json({ status: false, message: 'This upload belongs to a different account.' });
    }
    if (!intent.ownerId && identity.user) {
      return res.status(403).json({ status: false, message: 'This upload belongs to a different account.' });
    }

    if (intent.status === 'completed' || intent.status === 'completing') {
      const savedFile = await db.collection('files').findOne({ intentId });
      if (savedFile) {
        await intents.updateOne(
          { _id: intentId, status: 'completing' },
          { $set: { status: 'completed', fileId: savedFile._id, updatedAt: new Date() } }
        );
        return res.json({
          status: true,
          data: {
            id: savedFile._id.toString(),
            filename: savedFile.originalFilename || savedFile.filename,
            url: savedFile.key ? getPublicUrl(savedFile.key) : savedFile.publicUrl,
            pageUrl: `/data/${savedFile._id}`,
          },
        });
      }
      if (intent.status === 'completed') throw new Error('Completed upload is missing its metadata record.');
    }
    if (intent.status !== 'pending' || intent.expiresAt <= new Date()) {
      return res.status(409).json({ status: false, message: 'Upload intent is no longer active.' });
    }

    const user = identity.user;
    if (intent.expiresIn === 'never' && (!user || !isPaidPermissionActive(user))) {
      return res.status(403).json({ status: false, message: 'Permanent storage permission is not active.' });
    }

    const claim = await intents.updateOne(
      { _id: intentId, status: 'pending', expiresAt: { $gt: new Date() } },
      { $set: { status: 'completing', updatedAt: new Date() } }
    );
    if (claim.modifiedCount !== 1) {
      return res.status(409).json({ status: false, message: 'Upload is already being completed.' });
    }

    let classBReserved;
    try {
      classBReserved = await reserveR2ClassBOperation(db);
    } catch (error) {
      await intents.updateOne(
        { _id: intentId, status: 'completing' },
        { $set: { status: 'pending', updatedAt: new Date() } }
      );
      throw error;
    }
    if (!classBReserved) {
      await intents.updateOne(
        { _id: intentId, status: 'completing' },
        { $set: { status: 'pending', updatedAt: new Date() } }
      );
      return res.status(429).json({
        status: false,
        message: 'File verification is paused at the monthly R2 operation safety limit.',
      });
    }

    let remoteObject;
    try {
      remoteObject = await headObject(intent.key);
    } catch (error) {
      await intents.updateOne({ _id: intentId, status: 'completing' }, { $set: { status: 'pending' } });
      if (error.name === 'NotFound' || error.name === 'NoSuchKey' || error.$metadata?.httpStatusCode === 404) {
        return res.status(400).json({ status: false, message: 'The file has not reached R2 yet.' });
      }
      throw error;
    }

    if (remoteObject.ContentLength !== intent.size || remoteObject.ContentType !== intent.contentType) {
      await trackR2ClassAOperation(db);
      await deleteObject(intent.key);
      await intents.updateOne(
        { _id: intentId, status: 'completing' },
        { $set: { status: 'rejected', updatedAt: new Date() } }
      );
      if (intent.ownerId) await releaseUserStorage(intent.ownerId, intent.size);
      await releaseR2Storage(db, intent.size);
      return res.status(400).json({ status: false, message: 'Uploaded file size or content type did not match the request.' });
    }

    const dbExpiration = EXPIRATION_OPTIONS[intent.expiresIn].milliseconds;
    const uploadedAt = new Date();
    const file = {
      filename: intent.filename,
      originalFilename: intent.originalFilename,
      key: intent.key,
      publicUrl: intent.publicUrl,
      contentType: intent.contentType,
      length: intent.size,
      uploadDate: uploadedAt,
      intentId,
      metadata: {
        expiresAt: dbExpiration === null ? null : new Date(uploadedAt.getTime() + dbExpiration),
        ...(intent.ownerId ? { ownerId: intent.ownerId } : {}),
      },
    };

    const saved = await db.collection('files').insertOne(file);
    await intents.updateOne(
      { _id: intentId, status: 'completing' },
      { $set: { status: 'completed', fileId: saved.insertedId, updatedAt: new Date() } }
    );
    return res.status(201).json({
      status: true,
      data: {
        id: saved.insertedId.toString(),
        filename: file.originalFilename,
        url: file.publicUrl,
        pageUrl: `/data/${saved.insertedId}`,
      },
    });
  } catch (error) {
    return next(error);
  }
});

// ---------- Upload (API, JSON response) ----------

app.post('/api/upload', enforceUploadIpLimits, legacyUploadMiddleware, uploadRateLimit, async (req, res) => {
  try {
    if (!req.files || !req.files.file) {
      return res.status(400).json({ status: false, message: 'No file uploaded.' });
    }
    const expiration = getExpiration(req.body && req.body.expiresIn);
    if (!expiration) {
      return res.status(400).json({ status: false, message: 'Invalid expiration option.' });
    }
    const apiAuth = await resolveApiKey(req);
    if (apiAuth.provided && !apiAuth.user) {
      return res.status(401).json({ status: false, message: 'Invalid API key.' });
    }
    if (expiration.option === 'never' && !apiAuth.user) {
      return res.status(401).json({ status: false, message: 'An account API key is required for permanent uploads.' });
    }
    if (expiration.option === 'never' && !isPaidPermissionActive(apiAuth.user)) {
      return res.status(403).json({ status: false, message: 'Permanent storage permission is not active.' });
    }

    const file = req.files.file;
    const filename = sanitizeUploadFilename(file.name);
    if (!filename) return res.status(400).json({ status: false, message: 'Invalid filename.' });
    const type = file.mimetype;
    const size = file.size;

    const bucket = await getBucket();
    await deleteExpiredFiles(bucket);
    const name = await uniqueName(bucket, filename);

    await saveUserFile(bucket, name, file.data, type, expiration.expiresAt, apiAuth.user);

    res.status(200).json({
      creator: 'Husky_dev',
      status: true,
      message: 'File uploaded successfully',
      data: {
        url: `${PUBLIC_BASE_URL}/${name}`,
        type,
        size: formatFileSize(size),
        expiresAt: expiration.expiresAt ? expiration.expiresAt.toISOString() : null,
      },
    });
  } catch (err) {
    if (err.code === 'STORAGE_QUOTA_EXCEEDED') {
      return res.status(413).json({ status: false, message: 'The account storage limit has been reached.' });
    }
    console.error(err);
    res.status(500).json({ status: false, message: 'Error uploading file.' });
  }
});

// ---------- Upload dari URL eksternal ----------

app.get('/api/upload/to', enforceUploadIpLimits, uploadRateLimit, async (req, res) => {
  try {
    const { url, namefile, expiresIn } = req.query;
    if (typeof url !== 'string' || !url) {
      return res.status(400).json({ status: false, message: 'URL not provided.' });
    }
    if (typeof namefile !== 'string' || !namefile) {
      return res.status(400).json({ status: false, message: 'Filename not provided.' });
    }
    const expiration = getExpiration(expiresIn);
    if (!expiration) {
      return res.status(400).json({ status: false, message: 'Invalid expiration option.' });
    }
    const apiAuth = await resolveApiKey(req);
    if (apiAuth.provided && !apiAuth.user) {
      return res.status(401).json({ status: false, message: 'Invalid API key.' });
    }
    if (expiration.option === 'never' && !apiAuth.user) {
      return res.status(401).json({ status: false, message: 'An account API key is required for permanent uploads.' });
    }
    if (expiration.option === 'never' && !isPaidPermissionActive(apiAuth.user)) {
      return res.status(403).json({ status: false, message: 'Permanent storage permission is not active.' });
    }

    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      maxContentLength: MAX_FILE_SIZE,
      maxBodyLength: MAX_FILE_SIZE,
    });

    const contentType = (response.headers['content-type'] || 'application/octet-stream').split(';')[0];
    const requestedFilename = sanitizeUploadFilename(namefile);
    if (!requestedFilename) return res.status(400).json({ status: false, message: 'Invalid filename.' });
    const extension = (contentType.split('/')[1] || 'bin').replace(/[^a-zA-Z0-9_-]/g, '') || 'bin';
    const filename = path.extname(requestedFilename)
      ? requestedFilename
      : `${requestedFilename}.${extension}`;
    const buffer = Buffer.from(response.data);

    if (buffer.length > MAX_FILE_SIZE) {
      return res.status(400).json({ status: false, message: 'Sorry, the downloaded file is too large.' });
    }

    const bucket = await getBucket();
    await deleteExpiredFiles(bucket);
    const name = await uniqueName(bucket, sanitizeUploadFilename(filename));
    await saveUserFile(bucket, name, buffer, contentType, expiration.expiresAt, apiAuth.user);

    res.status(200).json({
      creator: 'Husky_dev',
      status: true,
      message: 'File uploaded successfully',
      data: {
        url: `${PUBLIC_BASE_URL}/${name}`,
        type: contentType,
        size: formatFileSize(buffer.length),
        expiresAt: expiration.expiresAt ? expiration.expiresAt.toISOString() : null,
      },
    });
  } catch (err) {
    if (err.code === 'STORAGE_QUOTA_EXCEEDED') {
      return res.status(413).json({ status: false, message: 'The account storage limit has been reached.' });
    }
    console.error(err);
    res.status(500).json({ status: false, message: 'Error downloading the file.' });
  }
});

// ---------- Halaman detail file ----------

app.get('/data/:filename', async (req, res) => {
  try {
    const db = await getDb();
    const doc = (ObjectId.isValid(req.params.filename)
      ? await db.collection('files').findOne({ _id: new ObjectId(req.params.filename) })
      : null) || await findStoredFile(db, req.params.filename);
    if (!doc) return res.redirect('/');
    if (isExpired(doc)) {
      await deleteStoredFile(doc);
      return res.redirect('/');
    }

    res.render('data.ejs', {
      filename: doc.originalFilename || doc.filename,
      type: doc.contentType,
      size: formatFileSize(doc.length),
      fileUrl: doc.key
        ? getPublicUrl(doc.key)
        : doc.publicUrl || `${PUBLIC_BASE_URL}/${encodeURIComponent(doc.filename)}`,
      expiresAt: doc.metadata && doc.metadata.expiresAt
        ? doc.metadata.expiresAt.toISOString()
        : null,
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
  }
});

app.post('/api/r2/usage-event', async (req, res, next) => {
  const authorization = Buffer.from(req.get('authorization') || '');
  const expectedAuthorization = Buffer.from(`Bearer ${R2_USAGE_WEBHOOK_SECRET}`);
  if (
    !R2_USAGE_WEBHOOK_SECRET
    || authorization.length !== expectedAuthorization.length
    || !timingSafeEqual(authorization, expectedAuthorization)
  ) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }

  try {
    const { month, classB, blockedAtLimit } = req.body || {};
    if (
      typeof month !== 'string'
      || !/^\d{4}-\d{2}$/.test(month)
      || !Number.isSafeInteger(classB)
      || classB < 0
      || (blockedAtLimit !== undefined && typeof blockedAtLimit !== 'boolean')
    ) {
      return res.status(400).json({ status: false, message: 'Invalid usage event.' });
    }
    if (month !== currentUsageMonth()) {
      return res.status(409).json({ status: false, message: 'Usage event is for a different month.' });
    }
    const db = await getDb();
    await getCurrentR2Usage(db);
    await db.collection('r2_usage').updateOne(
      { _id: 'global', month },
      [{
        $set: {
          classB: { $max: [{ $ifNull: ['$classB', 0] }, classB] },
        },
      }]
    );
    const updatedUsage = await db.collection('r2_usage').findOne({ _id: 'global' });
    const alert90Sent = await sendUsageThresholdAlert(
      db,
      'classB90',
      updatedUsage.classB >= R2_CLASS_B_ALERT,
      'R2 Class B usage reached 90%',
      `Cloudflare Worker measured ${updatedUsage.classB.toLocaleString()} R2 Class B reads this month. Reads will be blocked at ${R2_CLASS_B_BLOCK.toLocaleString()} operations (95% of the stated free allowance).`
    );
    const alert95Sent = await sendUsageThresholdAlert(
      db,
      'classB95',
      updatedUsage.classB >= R2_CLASS_B_BLOCK || blockedAtLimit === true,
      'R2 Class B usage reached 95%',
      `Cloudflare Worker blocked R2 reads at ${updatedUsage.classB.toLocaleString()} Class B operations. Reads resume after the monthly counter resets.`
    );
    if (!alert90Sent || !alert95Sent) {
      return res.status(503).json({ status: false, message: 'Unable to deliver the R2 usage alert.' });
    }
    return res.json({ status: true });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/cleanup', async (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return res.status(503).json({ status: false, message: 'Cleanup is not configured.' });
  }

  const authorization = Buffer.from(req.get('authorization') || '');
  const expectedAuthorization = Buffer.from(`Bearer ${secret}`);
  if (
    authorization.length !== expectedAuthorization.length
    || !timingSafeEqual(authorization, expectedAuthorization)
  ) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }

  try {
    const bucket = await getBucket();
    const deleted = await deleteExpiredFiles(bucket);
    const expiredIntents = await cleanupExpiredUploadIntents();
    res.json({ status: true, deleted, expiredIntents });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: 'Cleanup failed.' });
  }
});

// ---------- Serve files from R2 or legacy GridFS ----------

app.get('/:filename', async (req, res, next) => {
  try {
    const db = await getDb();
    const doc = await findStoredFile(db, req.params.filename);
    if (!doc) return next();
    if (isExpired(doc)) {
      await deleteStoredFile(doc);
      return next();
    }

    if (doc.key) {
      return res.redirect(302, getPublicUrl(doc.key));
    }

    const bucket = await getBucket();
    res.set('Content-Type', doc.contentType || 'application/octet-stream');
    res.set(
      'Cache-Control',
      doc.metadata && doc.metadata.expiresAt
        ? 'no-store'
        : 'public, max-age=31536000, immutable'
    );
    bucket.openDownloadStreamByName(req.params.filename).pipe(res);
  } catch (err) {
    console.error(err);
    next();
  }
});

app.use((req, res) => {
  res.status(404).render('404.ejs');
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.clear();
    cfonts.say('Husky_dev', {
      font: 'block',
      align: 'center',
      colors: ['blueBright', 'cyan'],
      background: 'transparent',
      letterSpacing: 1,
      lineHeight: 1.5,
      space: true,
      maxLength: '0',
      gradient: true,
      independentGradient: false,
      transitionGradient: false,
      env: 'node',
    });
    console.log('\x1b[36m%s\x1b[0m', 'Project by : Husky_dev');
    console.log('\x1b[33m%s\x1b[0m', 'CDN Deskripsi : Media Hosting');
    console.log('\x1b[33m%s\x1b[0m', 'CDN Support : Mp3, Mp4, Image, File');
    console.log('\x1b[35m%s\x1b[0m', `Server Online. port ${PORT}`);
  });
}

module.exports = app;
