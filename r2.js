// r2.js — Cloudflare R2 storage client for FORCAP MARIDE
// S3-compatible, used for persistent PDF and sidecar storage.
//
// Required env vars:
//   R2_ACCOUNT_ID        — Cloudflare account ID
//   R2_ACCESS_KEY_ID     — R2 API token access key
//   R2_SECRET_ACCESS_KEY — R2 API token secret
//   R2_BUCKET_NAME       — bucket name (default: forcap-manuals)
//
// Key layout in bucket:
//   manuals/{storedName}        — PDF files
//   sidecars/{storedName}.txt   — extracted text sidecars

'use strict';

const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const R2_ACCOUNT_ID       = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID    = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY= process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET           = process.env.R2_BUCKET_NAME || 'forcap-manuals';
const R2_ENDPOINT         = process.env.R2_ENDPOINT
  || (R2_ACCOUNT_ID ? `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : null);

function isEnabled() {
  return !!(R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_ENDPOINT);
}

let _client = null;
function getClient() {
  if (_client) return _client;
  if (!isEnabled()) return null;
  _client = new S3Client({
    region: 'auto',
    endpoint: R2_ENDPOINT,
    credentials: {
      accessKeyId:     R2_ACCESS_KEY_ID,
      secretAccessKey: R2_SECRET_ACCESS_KEY,
    },
  });
  return _client;
}

// ── Upload ────────────────────────────────────────────────────────────────────
async function uploadFile(key, body, contentType = 'application/octet-stream') {
  const client = getClient();
  if (!client) throw new Error('R2 not configured');
  await client.send(new PutObjectCommand({
    Bucket:      R2_BUCKET,
    Key:         key,
    Body:        body,
    ContentType: contentType,
  }));
  return key;
}

// Convenience wrappers
async function uploadPdf(storedName, buffer) {
  return uploadFile(`manuals/${storedName}`, buffer, 'application/pdf');
}

async function uploadSidecar(storedName, text) {
  return uploadFile(`sidecars/${storedName}.txt`, Buffer.from(text, 'utf8'), 'text/plain; charset=utf-8');
}

// ── Download ──────────────────────────────────────────────────────────────────
async function downloadFile(key) {
  const client = getClient();
  if (!client) throw new Error('R2 not configured');
  const resp = await client.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: key }));
  const chunks = [];
  for await (const chunk of resp.Body) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function downloadPdf(storedName) {
  return downloadFile(`manuals/${storedName}`);
}

async function downloadSidecar(storedName) {
  const buf = await downloadFile(`sidecars/${storedName}.txt`);
  return buf.toString('utf8');
}

// ── Delete ────────────────────────────────────────────────────────────────────
async function deleteManualFiles(storedName) {
  const client = getClient();
  if (!client) return;
  const keys = [`manuals/${storedName}`, `sidecars/${storedName}.txt`];
  for (const key of keys) {
    await client.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }))
      .catch(e => console.error(`[R2] Delete ${key} failed:`, e.message));
  }
}

// ── Presigned URL (for file serve) ───────────────────────────────────────────
async function getPresignedUrl(storedName, expiresIn = 3600) {
  const client = getClient();
  if (!client) throw new Error('R2 not configured');
  return getSignedUrl(
    client,
    new GetObjectCommand({ Bucket: R2_BUCKET, Key: `manuals/${storedName}` }),
    { expiresIn }
  );
}

module.exports = {
  isEnabled,
  uploadPdf,
  uploadSidecar,
  downloadPdf,
  downloadSidecar,
  deleteManualFiles,
  getPresignedUrl,
  // Generic
  uploadFile,
  downloadFile,
};
