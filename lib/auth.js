/**
 * BRMSTE™ Gateway — Shared Security Library
 * ==========================================
 * API key validation, HMAC request signing, rate limiting.
 * This file runs on Vercel ONLY. Contains ZERO BRM logic.
 */

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════
// API KEY MANAGEMENT
// ═══════════════════════════════════════════════════════════

// In production, replace with Vercel KV / Postgres
// For now: environment variable with JSON-encoded key hashes
function getKeyStore() {
  try {
    return JSON.parse(process.env.BRMSTE_API_KEYS || '{}');
  } catch {
    return {};
  }
}

function hashKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

function validateApiKey(authHeader) {
  if (!authHeader) return { valid: false, error: 'Missing Authorization header' };

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return { valid: false, error: 'Invalid Authorization format. Use: Bearer <api_key>' };
  }

  const rawKey = parts[1];
  if (!rawKey.startsWith('brm_')) {
    return { valid: false, error: 'Invalid API key format' };
  }

  const keyHash = hashKey(rawKey);
  const store = getKeyStore();
  const keyData = store[keyHash];

  if (!keyData) return { valid: false, error: 'Invalid API key' };
  if (!keyData.active) return { valid: false, error: 'API key deactivated' };

  return {
    valid: true,
    customer: keyData.customer,
    tier: keyData.tier,
    keyHash,
  };
}

// ═══════════════════════════════════════════════════════════
// HMAC REQUEST SIGNING (Vercel → BRM Engine)
// ═══════════════════════════════════════════════════════════

function signRequest(payload) {
  const secret = process.env.BRMSTE_TUNNEL_SECRET;
  if (!secret) throw new Error('BRMSTE_TUNNEL_SECRET not configured');

  const timestamp = Math.floor(Date.now() / 1000);
  const body = JSON.stringify(payload);
  const message = `${timestamp}.${body}`;
  const signature = crypto.createHmac('sha256', secret).update(message).digest('hex');

  return { timestamp, signature, body };
}

// ═══════════════════════════════════════════════════════════
// RATE LIMITING (in-memory, per serverless instance)
// For production: use Vercel KV (Upstash Redis)
// ═══════════════════════════════════════════════════════════

const rateLimits = new Map();

const TIER_LIMITS = {
  demo:       { perMinute: 3,   perDay: 3,      tokensPerMonth: 10000 },
  developer:  { perMinute: 20,  perDay: 500,    tokensPerMonth: 1000000 },
  pro:        { perMinute: 60,  perDay: 5000,   tokensPerMonth: 50000000 },
  enterprise: { perMinute: 200, perDay: 50000,  tokensPerMonth: 999999999 },
};

function checkRateLimit(identifier, tier = 'demo') {
  const limits = TIER_LIMITS[tier] || TIER_LIMITS.demo;
  const now = Date.now();
  const windowKey = `${identifier}:${Math.floor(now / 60000)}`;

  const record = rateLimits.get(windowKey) || { count: 0 };
  record.count++;
  rateLimits.set(windowKey, record);

  // Clean old entries
  if (rateLimits.size > 10000) {
    const cutoff = now - 120000;
    for (const [key, val] of rateLimits) {
      const ts = parseInt(key.split(':').pop()) * 60000;
      if (ts < cutoff) rateLimits.delete(key);
    }
  }

  if (record.count > limits.perMinute) {
    return { allowed: false, error: 'Rate limit exceeded', retryAfter: 60 };
  }

  return { allowed: true, remaining: limits.perMinute - record.count };
}

// ═══════════════════════════════════════════════════════════
// SECURITY HEADERS
// ═══════════════════════════════════════════════════════════

function setSecurityHeaders(res) {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.cdnfonts.com; font-src 'self' https://fonts.cdnfonts.com https://fonts.gstatic.com;");
  res.setHeader('X-Powered-By', 'BRMSTE');
}

// ═══════════════════════════════════════════════════════════
// ADMIN AUTH (simple shared secret for admin endpoints)
// ═══════════════════════════════════════════════════════════

function validateAdmin(authHeader) {
  if (!authHeader) return false;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return false;
  return parts[1] === process.env.BRMSTE_ADMIN_SECRET;
}

// ═══════════════════════════════════════════════════════════
// AUDIT LOG
// ═══════════════════════════════════════════════════════════

function auditLog(event) {
  const entry = {
    timestamp: new Date().toISOString(),
    ...event,
  };
  // In production: send to Vercel Log Drain / Datadog / etc
  console.log(`[AUDIT] ${JSON.stringify(entry)}`);
}

module.exports = {
  validateApiKey,
  hashKey,
  signRequest,
  checkRateLimit,
  setSecurityHeaders,
  validateAdmin,
  auditLog,
  TIER_LIMITS,
};
