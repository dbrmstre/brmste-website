/**
 * BRMSTE™ — Production API Endpoint
 * ===================================
 * POST /api/v1/reason
 * 
 * This is what Ishan, customers, and integrations call.
 * It validates the API key, checks rate limits, forwards to the
 * BRM engine via encrypted tunnel, and returns ONLY the result.
 * 
 * CONTAINS ZERO BRM LOGIC. This is just a gateway.
 * 
 * Usage:
 *   curl -X POST https://api.brmste.ai/api/v1/reason \
 *     -H "Authorization: Bearer brm_pro_xxxx" \
 *     -H "Content-Type: application/json" \
 *     -d '{"text": "Your scenario here"}'
 */

const { validateApiKey, signRequest, checkRateLimit, setSecurityHeaders, auditLog } = require('../../lib/auth');

module.exports = async function handler(req, res) {
  setSecurityHeaders(res);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed', allowed: ['POST'] });
  }

  // ── STEP 1: AUTHENTICATE ──
  const auth = validateApiKey(req.headers.authorization);
  if (!auth.valid) {
    auditLog({ event: 'AUTH_FAILED', error: auth.error, ip: req.headers['x-forwarded-for'] });
    return res.status(401).json({ error: auth.error });
  }

  // ── STEP 2: RATE LIMIT ──
  const limit = checkRateLimit(auth.keyHash, auth.tier);
  res.setHeader('X-RateLimit-Limit', limit.allowed ? 'ok' : 'exceeded');
  res.setHeader('X-RateLimit-Remaining', String(limit.remaining || 0));

  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfter || 60));
    auditLog({ event: 'RATE_LIMITED', customer: auth.customer, tier: auth.tier });
    return res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: limit.retryAfter,
      tier: auth.tier,
    });
  }

  // ── STEP 3: VALIDATE INPUT ──
  const { text, context, history } = req.body || {};
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return res.status(400).json({ error: 'Missing required field: text' });
  }
  if (text.length > 5000) {
    return res.status(400).json({ error: 'Text exceeds 5000 character limit' });
  }

  // ── STEP 4: SIGN AND FORWARD TO BRM ENGINE ──
  const tunnelUrl = process.env.BRMSTE_TUNNEL_URL;
  if (!tunnelUrl) {
    auditLog({ event: 'CONFIG_ERROR', message: 'BRMSTE_TUNNEL_URL not set' });
    return res.status(503).json({ error: 'Service temporarily unavailable' });
  }

  const payload = {
    query: text.trim(),
    context: context ? String(context).substring(0, 2000) : undefined,
    customer: auth.customer,
    tier: auth.tier,
  };

  const signed = signRequest(payload);

  try {
    const response = await fetch(`${tunnelUrl}/process`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-BRMSTE-Timestamp': String(signed.timestamp),
        'X-BRMSTE-Signature': signed.signature,
      },
      body: signed.body,
      signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => 'Unknown error');
      auditLog({ event: 'ENGINE_ERROR', status: response.status, customer: auth.customer });
      return res.status(502).json({ error: 'Analysis engine error', detail: response.status });
    }

    const result = await response.json();

    // ── STEP 5: LOG AND RETURN ──
    auditLog({
      event: 'REQUEST_COMPLETE',
      customer: auth.customer,
      tier: auth.tier,
      route: result.route,
      tokensUsed: result.tokens_used || 0,
      latencyMs: Date.now() - (signed.timestamp * 1000),
    });

    return res.status(200).json({
      result: result.result,
      tokens_used: result.tokens_used || 0,
      model: 'brmste-v21',
      // Internal architecture details never exposed
    });

  } catch (err) {
    if (err.name === 'AbortError' || err.name === 'TimeoutError') {
      auditLog({ event: 'TIMEOUT', customer: auth.customer });
      return res.status(504).json({ error: 'Analysis timed out. Please try again.' });
    }
    auditLog({ event: 'NETWORK_ERROR', message: err.message, customer: auth.customer });
    return res.status(502).json({ error: 'Engine unreachable. Please try again shortly.' });
  }
};
