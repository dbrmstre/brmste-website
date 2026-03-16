/**
 * BRMSTE™ — Demo Chat API (Email-gated)
 * Rate limited by email. 3 queries per email, ever.
 */

const { signRequest, setSecurityHeaders, auditLog } = require('../lib/auth');

const emailUsage = new Map();
const MAX_QUERIES = 3;

module.exports = async function handler(req, res) {
  setSecurityHeaders(res);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const body = req.body || {};

  // LEAD CAPTURE
  if (body.type === 'lead') {
    auditLog({ event: 'NEW_LEAD', email: body.email, name: body.name || 'Unknown' });
    if (!emailUsage.has(body.email)) emailUsage.set(body.email, { count: 0, name: body.name || 'Unknown' });
    return res.status(200).json({ status: 'ok' });
  }

  // TRANSCRIPT SAVE
  if (body.type === 'transcript') {
    auditLog({ event: 'DEMO_COMPLETE', email: body.email, name: body.name, transcript: JSON.stringify(body.transcript || []) });
    return res.status(200).json({ status: 'ok' });
  }

  // QUERY
  const { message, email, name, history } = body;
  if (!message || !email) return res.status(400).json({ error: 'Message and email required' });
  if (message.length > 2000) return res.status(400).json({ error: 'Message too long' });

  const usage = emailUsage.get(email) || { count: 0, name: name || 'Unknown' };
  if (usage.count >= MAX_QUERIES) {
    return res.status(429).json({ error: 'Your 3 complimentary analyses are complete. Our team will follow up.', remaining: 0 });
  }

  usage.count++;
  emailUsage.set(email, usage);

  const tunnelUrl = process.env.BRMSTE_TUNNEL_URL;
  if (!tunnelUrl) return res.status(503).json({ error: 'Service temporarily unavailable' });

  const signed = signRequest({ query: message.trim(), customer: 'demo:' + email, tier: 'demo' });

  try {
    const response = await fetch(`${tunnelUrl}/process`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BRMSTE-Timestamp': String(signed.timestamp), 'X-BRMSTE-Signature': signed.signature },
      body: signed.body,
      signal: AbortSignal.timeout(25000),
    });

    if (!response.ok) {
      usage.count--;
      emailUsage.set(email, usage);
      return res.status(502).json({ error: 'Analysis engine temporarily unavailable.' });
    }

    const result = await response.json();
    const remaining = MAX_QUERIES - usage.count;
    auditLog({ event: 'DEMO_QUERY', email, queryNumber: usage.count, remaining });
    return res.status(200).json({ response: result.result, remaining });
  } catch (err) {
    usage.count--;
    emailUsage.set(email, usage);
    return res.status(502).json({ error: 'Engine temporarily unavailable.' });
  }
};
