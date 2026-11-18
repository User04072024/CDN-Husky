const {
  CopyObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

let client;
let config;

function getConfig() {
  if (config) return config;

  const required = [
    'R2_ACCOUNT_ID',
    'R2_ACCESS_KEY_ID',
    'R2_SECRET_ACCESS_KEY',
    'R2_BUCKET',
    'R2_PUBLIC_URL',
    'R2_GATEWAY_URL',
  ];
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length) {
    throw new Error(`Missing Cloudflare R2 configuration: ${missing.join(', ')}`);
  }
  if (!/^[a-f0-9]{32}$/i.test(process.env.R2_ACCOUNT_ID)) {
    throw new Error('R2_ACCOUNT_ID must be the 32-character Cloudflare account ID.');
  }

  const publicUrl = new URL(process.env.R2_PUBLIC_URL);
  const gatewayUrl = new URL(process.env.R2_GATEWAY_URL);
  if (
    !['http:', 'https:'].includes(publicUrl.protocol)
    || publicUrl.username
    || publicUrl.password
    || publicUrl.pathname !== '/'
    || publicUrl.search
    || publicUrl.hash
  ) {
    throw new Error('R2_PUBLIC_URL must be a root HTTP(S) custom-domain URL without credentials, path, query, or fragment.');
  }
  if (
    gatewayUrl.protocol !== 'https:'
    || gatewayUrl.username
    || gatewayUrl.password
    || gatewayUrl.pathname !== '/'
    || gatewayUrl.search
    || gatewayUrl.hash
    || gatewayUrl.origin !== publicUrl.origin
  ) {
    throw new Error('R2_GATEWAY_URL must be the same root HTTPS custom domain as R2_PUBLIC_URL.');
  }

  config = {
    accountId: process.env.R2_ACCOUNT_ID,
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
    bucket: process.env.R2_BUCKET,
    publicUrl: publicUrl.toString().replace(/\/+$/, ''),
  };
  return config;
}

function getClient() {
  if (!client) {
    const settings = getConfig();
    client = new S3Client({
      region: 'auto',
      endpoint: `https://${settings.accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: settings.accessKeyId,
        secretAccessKey: settings.secretAccessKey,
      },
    });
  }
  return client;
}

function getPublicUrl(key) {
  const settings = getConfig();
  const encodedKey = key.split('/').map(encodeURIComponent).join('/');
  return `${settings.publicUrl}/${encodedKey}`;
}

async function createUploadUrl(key, contentType, size, expiresAt) {
  const settings = getConfig();
  const command = new PutObjectCommand({
    Bucket: settings.bucket,
    Key: key,
    ContentType: contentType,
    ContentLength: size,
    IfNoneMatch: '*',
    ...(expiresAt ? { Metadata: { 'cdn-expires-at': expiresAt.toISOString() } } : {}),
  });
  return getSignedUrl(getClient(), command, {
    expiresIn: 5 * 60,
    signableHeaders: new Set(['content-type']),
    unhoistableHeaders: new Set(['x-amz-meta-cdn-expires-at']),
  });
}

async function headObject(key) {
  const settings = getConfig();
  return getClient().send(new HeadObjectCommand({
    Bucket: settings.bucket,
    Key: key,
  }));
}

async function deleteObject(key) {
  const settings = getConfig();
  return getClient().send(new DeleteObjectCommand({
    Bucket: settings.bucket,
    Key: key,
  }));
}

async function updateObjectExpiration(key, contentType, expiresAt) {
  const settings = getConfig();
  const encodedKey = key.split('/').map(encodeURIComponent).join('/');
  return getClient().send(new CopyObjectCommand({
    Bucket: settings.bucket,
    Key: key,
    CopySource: `${settings.bucket}/${encodedKey}`,
    MetadataDirective: 'REPLACE',
    ContentType: contentType || 'application/octet-stream',
    Metadata: expiresAt ? { 'cdn-expires-at': expiresAt.toISOString() } : {},
  }));
}

module.exports = {
  createUploadUrl,
  deleteObject,
  getPublicUrl,
  headObject,
  updateObjectExpiration,
};
