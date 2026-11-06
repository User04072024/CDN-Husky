const { MongoClient, GridFSBucket } = require('mongodb');

const uri = process.env.MONGODB_URI;

if (!uri) {
  throw new Error('MONGODB_URI belum di-set. Tambahkan connection string MongoDB Atlas kamu di environment variable.');
}

// Di serverless (Vercel), tiap invocation bisa reuse koneksi lama lewat `global`
// biar gak bikin koneksi baru ke Atlas tiap request (yang bikin lambat & boros).
let cachedClientPromise = global._mongoClientPromise;

if (!cachedClientPromise) {
  const client = new MongoClient(uri, {
    maxPoolSize: 10,
  });
  cachedClientPromise = client.connect();
  global._mongoClientPromise = cachedClientPromise;
}

async function getDb() {
  const client = await cachedClientPromise;
  // Nama database bisa diset lewat MONGODB_DB, atau diambil otomatis dari
  // connection string (mis. ".../cdn?retryWrites=..."). Kalau dua-duanya
  // kosong, driver fallback ke db 'test'.
  const dbName = process.env.MONGODB_DB;
  return dbName ? client.db(dbName) : client.db();
}

async function getBucket() {
  const db = await getDb();
  return new GridFSBucket(db, { bucketName: 'uploads' });
}

module.exports = { getDb, getBucket };
