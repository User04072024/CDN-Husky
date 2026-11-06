const {
  createHmac,
  randomBytes,
  timingSafeEqual,
} = require('crypto');
const { ObjectId } = require('mongodb');
const { getDb } = require('./mongodb');

const SESSION_COOKIE = 'husky_session';
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_INDEXES = new WeakMap();

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 characters.');
  }
  return secret;
}

function signSessionId(sessionId) {
  return createHmac('sha256', getSessionSecret()).update(sessionId).digest('hex');
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function getCookieValue(header, name) {
  const cookie = (header || '').split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return cookie ? cookie.slice(name.length + 1) : null;
}

async function ensureSessionIndexes(db) {
  if (!SESSION_INDEXES.has(db)) {
    SESSION_INDEXES.set(
      db,
      db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })
    );
  }
  await SESSION_INDEXES.get(db);
}

function sessionMiddleware() {
  return async (req, res, next) => {
    try {
      req.auth = null;
      const signedCookie = getCookieValue(req.headers.cookie, SESSION_COOKIE);
      if (!signedCookie) return next();

      const separator = signedCookie.lastIndexOf('.');
      if (separator <= 0) return next();
      const sessionId = signedCookie.slice(0, separator);
      const signature = signedCookie.slice(separator + 1);
      if (!/^[a-f0-9]{64}$/.test(sessionId) || !/^[a-f0-9]{64}$/.test(signature)) {
        return next();
      }
      if (!safeEqual(signature, signSessionId(sessionId))) return next();

      const db = await getDb();
      await ensureSessionIndexes(db);
      const session = await db.collection('sessions').findOne({
        _id: createHmac('sha256', getSessionSecret()).update(sessionId).digest('hex'),
        expiresAt: { $gt: new Date() },
      });
      if (!session) return next();

      if (session.role === 'admin') {
        req.auth = { role: 'admin', email: session.email };
        return next();
      }

      if (session.role === 'user' && ObjectId.isValid(session.userId)) {
        const user = await db.collection('users').findOne({
          _id: new ObjectId(session.userId),
          disabled: { $ne: true },
        });
        if (user) req.auth = { role: 'user', user };
      }
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

async function createSession(res, identity) {
  const db = await getDb();
  await ensureSessionIndexes(db);
  const sessionId = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS);
  const isProduction = process.env.NODE_ENV === 'production' || process.env.VERCEL;

  await db.collection('sessions').insertOne({
    _id: createHmac('sha256', getSessionSecret()).update(sessionId).digest('hex'),
    ...identity,
    createdAt: new Date(),
    expiresAt,
  });
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${sessionId}.${signSessionId(sessionId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DURATION_MS / 1000}${isProduction ? '; Secure' : ''}`
  );
}

async function destroySession(req, res) {
  const signedCookie = getCookieValue(req.headers.cookie, SESSION_COOKIE);
  if (signedCookie) {
    const separator = signedCookie.lastIndexOf('.');
    if (separator > 0) {
      const sessionId = signedCookie.slice(0, separator);
      const signature = signedCookie.slice(separator + 1);
      if (
        /^[a-f0-9]{64}$/.test(sessionId)
        && /^[a-f0-9]{64}$/.test(signature)
        && safeEqual(signature, signSessionId(sessionId))
      ) {
        const db = await getDb();
        await db.collection('sessions').deleteOne({
          _id: createHmac('sha256', getSessionSecret()).update(sessionId).digest('hex'),
        });
      }
    }
  }

  const isProduction = process.env.NODE_ENV === 'production' || process.env.VERCEL;
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${isProduction ? '; Secure' : ''}`
  );
}

function requireUser(req, res, next) {
  if (req.auth && req.auth.role === 'user') return next();
  if (req.accepts('html')) return res.redirect('/login');
  return res.status(401).json({ status: false, message: 'Login required.' });
}

function requireAdmin(req, res, next) {
  if (req.auth && req.auth.role === 'admin') return next();
  if (req.accepts('html')) return res.redirect('/admin/login');
  return res.status(401).json({ status: false, message: 'Admin login required.' });
}

module.exports = {
  createSession,
  destroySession,
  requireAdmin,
  requireUser,
  sessionMiddleware,
};
