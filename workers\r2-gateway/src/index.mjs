const CLASS_B_BLOCK = 9_500_000;
const CLASS_B_ALERT = 9_000_000;
const IP_15_MINUTE_LIMIT = 300;
const IP_DAILY_LIMIT = 3_000;

export default {
  async fetch(request, env) {
    if (!env.USAGE_WEBHOOK_SECRET) {
      return new Response('Download protection is not configured.', { status: 503 });
    }
    const url = new URL(request.url);
    if (url.pathname === '/_internal/usage') {
      if (
        !env.USAGE_WEBHOOK_SECRET
        || request.headers.get('Authorization') !== `Bearer ${env.USAGE_WEBHOOK_SECRET}`
      ) {
        return new Response('Unauthorized.', { status: 401 });
      }
      const counterId = env.USAGE_COUNTER.idFromName('global');
      return env.USAGE_COUNTER.get(counterId).fetch('https://counter.internal/usage');
    }
    if (url.pathname === '/_internal/charge-class-b') {
      if (
        !env.USAGE_WEBHOOK_SECRET
        || request.headers.get('Authorization') !== `Bearer ${env.USAGE_WEBHOOK_SECRET}`
      ) {
        return new Response('Unauthorized.', { status: 401 });
      }
      const counterId = env.USAGE_COUNTER.idFromName('global');
      const counter = env.USAGE_COUNTER.get(counterId);
      const chargeResponse = await counter.fetch('https://counter.internal/charge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operationCount: 1 }),
      });
      if (!chargeResponse.ok) return new Response('Usage counter unavailable.', { status: 503 });
      const charge = await chargeResponse.json();
      await reportUsageEvents(
        charge.alerts,
        charge.classB,
        charge.reason === 'monthly',
        env
      );
      return Response.json(charge, { status: charge.allowed ? 200 : 429 });
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method not allowed.', { status: 405, headers: { Allow: 'GET, HEAD' } });
    }

    const key = getObjectKey(new URL(request.url));
    if (!key) return new Response('Not found.', { status: 404 });

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const ipHash = await hashIp(ip, env.USAGE_WEBHOOK_SECRET);
    const operationCount = request.method === 'GET' && request.headers.has('Range') ? 2 : 1;
    const counterId = env.USAGE_COUNTER.idFromName('global');
    const counter = env.USAGE_COUNTER.get(counterId);
    const decisionResponse = await counter.fetch('https://counter.internal/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ipHash, operationCount }),
    });
    if (!decisionResponse.ok) {
      return new Response('Download protection is unavailable.', { status: 503 });
    }

    const decision = await decisionResponse.json();
    await reportUsageEvents(
      decision.alerts,
      decision.classB,
      decision.reason === 'monthly',
      env
    );
    if (!decision.allowed) {
      return new Response('Downloads are temporarily limited. Please try again later.', {
        status: decision.reason === 'ip' || decision.reason === 'monthly' ? 429 : 503,
        headers: {
          'Cache-Control': 'no-store',
          ...(decision.retryAfter ? { 'Retry-After': String(decision.retryAfter) } : {}),
        },
      });
    }

    try {
      return await serveObject(request, key, env.BUCKET);
    } catch (error) {
      console.error('R2 gateway read failed:', error);
      return new Response('File storage is temporarily unavailable.', { status: 502 });
    }
  },
};

export class UsageCounter {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS monthly_usage (
        month TEXT PRIMARY KEY,
        class_b INTEGER NOT NULL DEFAULT 0,
        alert_90_sent INTEGER NOT NULL DEFAULT 0,
        alert_95_sent INTEGER NOT NULL DEFAULT 0
      )
    `);
    const month = new Date().toISOString().slice(0, 7);
    const baselineMonth = env.CLASS_B_BASELINE_MONTH || '';
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(baselineMonth)) {
      throw new Error('Set CLASS_B_BASELINE_MONTH to the current YYYY-MM month before deploying the Worker.');
    }
    const parsedBaseline = Number(env.CLASS_B_BASELINE || 0);
    if (!Number.isSafeInteger(parsedBaseline) || parsedBaseline < 0) {
      throw new Error('CLASS_B_BASELINE must be a non-negative integer.');
    }
    const baseline = baselineMonth === month ? parsedBaseline : 0;
    this.ctx.storage.sql.exec(
      'INSERT OR IGNORE INTO monthly_usage (month, class_b) VALUES (?, ?)',
      month,
      baseline
    );
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS ip_windows (
        ip_hash TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        window_size INTEGER NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ip_hash, window_start, window_size)
      )
    `);
    this.ctx.storage.sql.exec(
      'CREATE INDEX IF NOT EXISTS ip_windows_expiry ON ip_windows(window_start)'
    );
  }

  async fetch(request) {
    const pathname = new URL(request.url).pathname;
    if (request.method === 'GET' && pathname === '/usage') {
      const month = new Date().toISOString().slice(0, 7);
      const [usage] = this.ctx.storage.sql.exec(
        'SELECT class_b FROM monthly_usage WHERE month = ?',
        month
      ).toArray();
      return Response.json({ month, classB: usage ? usage.class_b : 0 });
    }
    if (request.method !== 'POST') {
      return new Response('Not found.', { status: 404 });
    }
    if (pathname === '/ack') {
      const { alerts } = await request.json();
      this.ctx.storage.transactionSync(() => {
        for (const alert of alerts || []) {
          if (alert === 'classB90') {
            this.ctx.storage.sql.exec(
              'UPDATE monthly_usage SET alert_90_sent = 1 WHERE month = ?',
              new Date().toISOString().slice(0, 7)
            );
          } else if (alert === 'classB95') {
            this.ctx.storage.sql.exec(
              'UPDATE monthly_usage SET alert_95_sent = 1 WHERE month = ?',
              new Date().toISOString().slice(0, 7)
            );
          }
        }
      });
      return Response.json({ status: true });
    }
    if (pathname === '/charge') {
      const { operationCount } = await request.json();
      if (!Number.isInteger(operationCount) || operationCount < 1 || operationCount > 2) {
        return new Response('Invalid operation count.', { status: 400 });
      }
      const now = Date.now();
      const month = new Date(now).toISOString().slice(0, 7);
      const nowDate = new Date(now);
      const retryAfter = Math.ceil((
        Date.UTC(nowDate.getUTCFullYear(), nowDate.getUTCMonth() + 1, 1) - now
      ) / 1000);
      const result = this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(
          'INSERT OR IGNORE INTO monthly_usage (month) VALUES (?)',
          month
        );
        const [usage] = this.ctx.storage.sql.exec(
          'SELECT class_b, alert_90_sent, alert_95_sent FROM monthly_usage WHERE month = ?',
          month
        ).toArray();
        const nextCount = usage.class_b + operationCount;
        const alerts = [];
        if (nextCount >= CLASS_B_ALERT && !usage.alert_90_sent) alerts.push('classB90');
        if (usage.class_b >= CLASS_B_BLOCK || nextCount > CLASS_B_BLOCK) {
          if (!usage.alert_95_sent) alerts.push('classB95');
          return {
            allowed: false,
            reason: 'monthly',
            retryAfter,
            classB: usage.class_b,
            alerts,
          };
        }
        this.ctx.storage.sql.exec(
          'UPDATE monthly_usage SET class_b = ? WHERE month = ?',
          nextCount,
          month
        );
        if (nextCount >= CLASS_B_BLOCK && !usage.alert_95_sent) alerts.push('classB95');
        return { allowed: true, reason: null, classB: nextCount, alerts };
      });
      return Response.json(result);
    }
    if (pathname !== '/authorize') {
      return new Response('Not found.', { status: 404 });
    }
    const payload = await request.json();
    if (
      typeof payload.ipHash !== 'string'
      || !Number.isInteger(payload.operationCount)
      || payload.operationCount < 1
      || payload.operationCount > 2
    ) {
      return new Response('Invalid counter request.', { status: 400 });
    }

    const now = Date.now();
    const minuteWindow = 15 * 60 * 1000;
    const dayWindow = 24 * 60 * 60 * 1000;
    const minuteStart = Math.floor(now / minuteWindow) * minuteWindow;
    const dayStart = Math.floor(now / dayWindow) * dayWindow;
    const month = new Date(now).toISOString().slice(0, 7);
    const nowDate = new Date(now);
    const monthlyRetryAfter = Math.ceil((
      Date.UTC(nowDate.getUTCFullYear(), nowDate.getUTCMonth() + 1, 1) - now
    ) / 1000);
    const result = this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        'DELETE FROM ip_windows WHERE window_start < ?',
        now - dayWindow
      );
      this.ctx.storage.sql.exec(
        'INSERT OR IGNORE INTO monthly_usage (month) VALUES (?)',
        month
      );
      this.ctx.storage.sql.exec(
        'INSERT INTO ip_windows (ip_hash, window_start, window_size, count) VALUES (?, ?, ?, 1) '
          + 'ON CONFLICT(ip_hash, window_start, window_size) DO UPDATE SET count = count + 1',
        payload.ipHash,
        minuteStart,
        minuteWindow
      );
      this.ctx.storage.sql.exec(
        'INSERT INTO ip_windows (ip_hash, window_start, window_size, count) VALUES (?, ?, ?, 1) '
          + 'ON CONFLICT(ip_hash, window_start, window_size) DO UPDATE SET count = count + 1',
        payload.ipHash,
        dayStart,
        dayWindow
      );

      const [minuteCount] = this.ctx.storage.sql.exec(
        'SELECT count FROM ip_windows WHERE ip_hash = ? AND window_start = ? AND window_size = ?',
        payload.ipHash,
        minuteStart,
        minuteWindow
      ).toArray();
      const [dayCount] = this.ctx.storage.sql.exec(
        'SELECT count FROM ip_windows WHERE ip_hash = ? AND window_start = ? AND window_size = ?',
        payload.ipHash,
        dayStart,
        dayWindow
      ).toArray();
      const [usage] = this.ctx.storage.sql.exec(
        'SELECT class_b, alert_90_sent, alert_95_sent FROM monthly_usage WHERE month = ?',
        month
      ).toArray();

      if (minuteCount.count > IP_15_MINUTE_LIMIT || dayCount.count > IP_DAILY_LIMIT) {
        return {
          allowed: false,
          reason: 'ip',
          retryAfter: minuteCount.count > IP_15_MINUTE_LIMIT
            ? Math.ceil((minuteStart + minuteWindow - now) / 1000)
            : Math.ceil((dayStart + dayWindow - now) / 1000),
          classB: usage.class_b,
          alerts: [],
        };
      }

      if (usage.class_b >= CLASS_B_BLOCK) {
        const alerts = [];
        if (usage.class_b >= CLASS_B_ALERT && !usage.alert_90_sent) {
          alerts.push('classB90');
        }
        if (!usage.alert_95_sent) {
          alerts.push('classB95');
        }
        return {
          allowed: false,
          reason: 'monthly',
          retryAfter: monthlyRetryAfter,
          classB: usage.class_b,
          alerts,
        };
      }

      const nextCount = usage.class_b + payload.operationCount;
      if (nextCount > CLASS_B_BLOCK) {
        const alerts = [];
        if (nextCount >= CLASS_B_ALERT && !usage.alert_90_sent) alerts.push('classB90');
        if (!usage.alert_95_sent) alerts.push('classB95');
        return {
          allowed: false,
          reason: 'monthly',
          retryAfter: monthlyRetryAfter,
          classB: usage.class_b,
          alerts,
        };
      }

      this.ctx.storage.sql.exec(
        'UPDATE monthly_usage SET class_b = ? WHERE month = ?',
        nextCount,
        month
      );
      const alerts = [];
      if (nextCount >= CLASS_B_ALERT && !usage.alert_90_sent) {
        alerts.push('classB90');
      }
      if (nextCount >= CLASS_B_BLOCK && !usage.alert_95_sent) {
        alerts.push('classB95');
      }
      return { allowed: true, reason: null, classB: nextCount, alerts };
    });

    return Response.json(result);
  }
}

function getObjectKey(url) {
  const segments = url.pathname.split('/').filter(Boolean);
  if (segments.length !== 3) return null;
  try {
    const decoded = segments.map((segment) => decodeURIComponent(segment));
    if (
      decoded[0] !== 'uploads'
      || !/^[a-f0-9-]{36}$/i.test(decoded[1])
      || !decoded[2]
      || decoded.some((segment) => segment.includes('/') || segment.includes('\\'))
    ) {
      return null;
    }
    return decoded.join('/');
  } catch {
    return null;
  }
}

async function hashIp(ip, secret) {
  const bytes = new TextEncoder().encode(`${secret}:${ip}`);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function reportUsageEvents(alerts, classB, blockedAtLimit, env) {
  if (!alerts.length) return;
  if (!env.APP_USAGE_URL || !env.USAGE_WEBHOOK_SECRET) {
    console.error('R2 usage alert is pending; configure APP_USAGE_URL and USAGE_WEBHOOK_SECRET.');
    return;
  }
  try {
    const response = await fetch(env.APP_USAGE_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.USAGE_WEBHOOK_SECRET}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        month: new Date().toISOString().slice(0, 7),
        classB,
        blockedAtLimit,
      }),
    });
    if (!response.ok) {
      console.error(`R2 usage alert webhook returned HTTP ${response.status}.`);
      return;
    }
    const counter = env.USAGE_COUNTER.get(env.USAGE_COUNTER.idFromName('global'));
    await counter.fetch('https://counter.internal/ack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alerts }),
    });
  } catch (error) {
    console.error('Unable to deliver R2 usage alert:', error);
  }
}

function parseByteRange(value, size) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(value || '');
  if (!match || (!match[1] && !match[2])) return null;
  if (!match[1]) {
    const suffixLength = Number(match[2]);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return null;
    const length = Math.min(suffixLength, size);
    return { offset: size - length, length };
  }
  const offset = Number(match[1]);
  const end = match[2] ? Number(match[2]) : size - 1;
  if (
    !Number.isSafeInteger(offset)
    || !Number.isSafeInteger(end)
    || offset < 0
    || end < offset
    || offset >= size
  ) {
    return null;
  }
  return { offset, length: Math.min(end, size - 1) - offset + 1 };
}

async function serveObject(request, key, bucket) {
  const headers = new Headers({
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  let object;
  let range;
  if (request.method === 'HEAD') {
    object = await bucket.head(key);
  } else if (request.headers.has('Range')) {
    const metadata = await bucket.head(key);
    if (!metadata) return new Response('File not found.', { status: 404, headers });
    range = parseByteRange(request.headers.get('Range'), metadata.size);
    if (!range) {
      headers.set('Content-Range', `bytes */${metadata.size}`);
      return new Response(null, { status: 416, headers });
    }
    object = await bucket.get(key, { range });
  } else {
    object = await bucket.get(key);
  }
  if (!object) return new Response('File not found.', { status: 404, headers });

  const expiresAt = object.customMetadata && object.customMetadata['cdn-expires-at'];
  if (expiresAt && Number.isFinite(Date.parse(expiresAt)) && Date.parse(expiresAt) <= Date.now()) {
    return new Response('This file has expired.', { status: 410, headers });
  }
  object.writeHttpMetadata(headers);
  headers.set('ETag', object.httpEtag);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  if (range) {
    headers.set('Accept-Ranges', 'bytes');
    headers.set(
      'Content-Range',
      `bytes ${range.offset}-${range.offset + range.length - 1}/${object.size}`
    );
    headers.set('Content-Length', String(range.length));
  } else {
    headers.set('Content-Length', String(object.size));
  }
  return new Response(request.method === 'HEAD' ? null : object.body, {
    status: range ? 206 : 200,
    headers,
  });
}
