const {
  createHash,
  randomBytes,
  scrypt: scryptCallback,
  timingSafeEqual,
} = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(scryptCallback);

async function hashPassword(password) {
  const salt = randomBytes(16);
  const digest = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${digest.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  if (typeof storedHash !== 'string') return false;
  const [algorithm, saltHex, digestHex] = storedHash.split('$');
  if (
    algorithm !== 'scrypt'
    || !/^[a-f0-9]{32}$/.test(saltHex || '')
    || !/^[a-f0-9]{128}$/.test(digestHex || '')
  ) {
    return false;
  }

  const digest = await scrypt(password, Buffer.from(saltHex, 'hex'), 64);
  return timingSafeEqual(digest, Buffer.from(digestHex, 'hex'));
}

function hashApiKey(apiKey) {
  return createHash('sha256').update(apiKey).digest('hex');
}

function createApiKey() {
  const key = `hdev_${randomBytes(32).toString('base64url')}`;
  return { key, hash: hashApiKey(key), prefix: key.slice(0, 13) };
}

module.exports = {
  createApiKey,
  hashApiKey,
  hashPassword,
  verifyPassword,
};
