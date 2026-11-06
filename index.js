require('dotenv').config();

const express = require('express');
const fileUpload = require('express-fileupload');
const favicon = require('serve-favicon');
const axios = require('axios');
const path = require('path');
const {
  createHash,
  randomBytes,
  timingSafeEqual,
} = require('crypto');
const cfonts = require('cfonts');
const nodemailer = require('nodemailer');
const { rateLimit } = require('express-rate-limit');
const { ObjectId } = require('mongodb');
const { getBucket, getDb } = require('./lib/mongodb');
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
const DEFAULT_EXPIRATION = '12h';
const MAX_USER_STORAGE_BYTES = 100 * 1024 * 1024 * 1024;
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

// Batas ukuran file. Kalau di-deploy ke Vercel, body request Serverless
// Function DIBATASI KERAS 4.5MB oleh infrastrukturnya (gak bisa diubah dari
// kode/config), jadi default di sini 4MB. Kalau host di server sendiri
// (VPS/PM2/dll), boleh dinaikkan lewat env MAX_FILE_SIZE (dalam bytes).
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10) || 4 * 1024 * 1024;

app.use(
  fileUpload({
    createParentPath: true,
    useTempFiles: false, // simpan buffer di memory, JANGAN nulis ke disk (Vercel read-only)
    limits: { fileSize: MAX_FILE_SIZE },
    abortOnLimit: true,
  })
);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use(favicon(path.join(__dirname, 'assets', 'img', 'favicon.ico')));
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
      ])
    );
  }
  await ACCOUNT_INDEXES.get(db);
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
  const bucket = await getBucket();
  const db = await getDb();
  const page = getPage(options.page);
  const pageSize = 50;
  const fileFilter = { 'metadata.ownerId': user._id };
  const [files, fileCount, paymentRequest] = await Promise.all([
    bucket.find(fileFilter).sort({ uploadDate: -1 }).skip((page - 1) * pageSize).limit(pageSize).toArray(),
    db.collection('uploads.files').countDocuments(fileFilter),
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
    const bucket = await getBucket();
    const file = await bucket.find({
      _id: new ObjectId(req.params.id),
      'metadata.ownerId': req.auth.user._id,
    }).limit(1).next();
    if (!file) return res.status(404).send('File not found.');
    await deleteGridFSFile(bucket, file);
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
    const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const submittedEmail = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!adminEmail || !process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
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

      const port = Number(process.env.SMTP_PORT || 587);
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port,
        secure: process.env.SMTP_SECURE === 'true' || port === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      });
      const verificationUrl = `${PUBLIC_BASE_URL}/admin/verify?token=${token}`;
      await transporter.sendMail({
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
    if (!loginToken || loginToken.email !== (process.env.ADMIN_EMAIL || '').trim().toLowerCase()) {
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
    const [users, userCount, requests, requestCount, files, fileCount] = await Promise.all([
      db.collection('users').find({}).sort({ createdAt: -1 }).skip((accountsPage - 1) * pageSize).limit(pageSize).toArray(),
      db.collection('users').countDocuments({}),
      db.collection('payment_requests').find({ status: 'pending' }).sort({ createdAt: 1 }).skip((requestsPage - 1) * pageSize).limit(pageSize).toArray(),
      db.collection('payment_requests').countDocuments({ status: 'pending' }),
      (await getBucket()).find({}).sort({ uploadDate: -1 }).skip((filesPage - 1) * pageSize).limit(pageSize).toArray(),
      db.collection('uploads.files').countDocuments({}),
    ]);
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
    const bucket = await getBucket();
    const file = await bucket.find({ _id: new ObjectId(req.params.id) }).limit(1).next();
    if (!file) return res.status(404).send('File not found.');
    await deleteGridFSFile(bucket, file);
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

function cleanFileName(originalName) {
  return originalName.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9-_]/g, '-');
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

async function deleteExpiredFiles(bucket, limit = 100) {
  const expiredFiles = await bucket
    .find({ 'metadata.expiresAt': { $lte: new Date() } })
    .limit(limit)
    .toArray();

  for (const file of expiredFiles) {
    await deleteGridFSFile(bucket, file);
  }

  return expiredFiles.length;
}

async function uniqueName(bucket, base, ext) {
  let name = `${base}.${ext}`;
  let number = 0;
  while (await findFileDoc(bucket, name)) {
    number += 1;
    name = `${base}-${number}.${ext}`;
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

// ---------- Upload (form, dipakai halaman utama) ----------

app.post('/upload', requireSameOrigin, uploadRateLimit, async (req, res) => {
  try {
    if (!req.files || !req.files.file) {
      return res.status(400).send('No file uploaded.');
    }
    const expiration = getExpiration(req.body && req.body.expiresIn);
    if (!expiration) {
      return res.status(400).send('Invalid expiration option.');
    }
    const user = req.auth && req.auth.role === 'user' ? req.auth.user : null;
    if (expiration.option === 'never' && !user) {
      return res.redirect('/login?next=permanent');
    }
    if (expiration.option === 'never' && !isPaidPermissionActive(user)) {
      return res.redirect('/account?payment=required');
    }

    const file = req.files.file;
    const fileExtension = file.name.split('.').pop();
    const base = generateRandomFileName(8);
    const type = file.mimetype;

    const bucket = await getBucket();
    await deleteExpiredFiles(bucket);
    const name = await uniqueName(bucket, base, fileExtension);

    await saveUserFile(bucket, name, file.data, type, expiration.expiresAt, user);

    res.redirect('/data/' + name);
  } catch (err) {
    if (err.code === 'STORAGE_QUOTA_EXCEEDED') {
      return res.redirect('/account?quota=exceeded');
    }
    console.error(err);
    res.status(500).send('Terjadi kesalahan saat upload.');
  }
});

// ---------- Upload (API, JSON response) ----------

app.post('/api/upload', uploadRateLimit, async (req, res) => {
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
    const fileExtension = file.name.split('.').pop();
    const base = cleanFileName(file.name);
    const type = file.mimetype;
    const size = file.size;

    const bucket = await getBucket();
    await deleteExpiredFiles(bucket);
    const name = await uniqueName(bucket, base, fileExtension);

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

app.get('/api/upload/to', uploadRateLimit, async (req, res) => {
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

    const contentType = response.headers['content-type'] || 'application/octet-stream';
    const fileExtension = contentType.split('/')[1] || 'bin';
    const base = cleanFileName(namefile);
    const buffer = Buffer.from(response.data);

    if (buffer.length > MAX_FILE_SIZE) {
      return res.status(400).json({ status: false, message: 'Sorry, the downloaded file is too large.' });
    }

    const bucket = await getBucket();
    await deleteExpiredFiles(bucket);
    const name = await uniqueName(bucket, base, fileExtension);
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
    const bucket = await getBucket();
    const doc = await findFileDoc(bucket, req.params.filename);
    if (!doc) return res.redirect('/');
    if (isExpired(doc)) {
      await deleteGridFSFile(bucket, doc);
      return res.redirect('/');
    }

    res.render('data.ejs', {
      filename: doc.filename,
      type: doc.contentType,
      size: formatFileSize(doc.length),
      baseUrl: PUBLIC_BASE_URL,
      expiresAt: doc.metadata && doc.metadata.expiresAt
        ? doc.metadata.expiresAt.toISOString()
        : null,
    });
  } catch (err) {
    console.error(err);
    res.redirect('/');
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
    res.json({ status: true, deleted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: false, message: 'Cleanup failed.' });
  }
});

// ---------- Serve file langsung dari GridFS ----------

app.get('/:filename', async (req, res, next) => {
  try {
    const bucket = await getBucket();
    const doc = await findFileDoc(bucket, req.params.filename);
    if (!doc) return next();
    if (isExpired(doc)) {
      await deleteGridFSFile(bucket, doc);
      return next();
    }

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
