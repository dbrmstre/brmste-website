/**
 * BRMSTE™ — Admin: API Key Management
 * =====================================
 * POST /api/admin/keys   — Generate new key
 * GET  /api/admin/keys    — List all keys
 * DELETE /api/admin/keys  — Revoke a key
 * 
 * Protected by BRMSTE_ADMIN_SECRET. Only SB can access this.
 */

const crypto = require('crypto');
const { validateAdmin, hashKey, setSecurityHeaders, auditLog } = require('../../lib/auth');

// Generate a cryptographically secure API key
function generateApiKey(tier) {
  const raw = crypto.randomBytes(32).toString('base64url');
  return `brm_${tier}_${raw}`;
}

module.exports = async function handler(req, res) {
  setSecurityHeaders(res);

  // Admin auth required
  if (!validateAdmin(req.headers.authorization)) {
    return res.status(401).json({ error: 'Admin access required' });
  }

  if (req.method === 'POST') {
    // ── GENERATE NEW KEY ──
    const { customer, tier = 'developer' } = req.body || {};
    if (!customer) return res.status(400).json({ error: 'Customer name required' });
    if (!['developer', 'pro', 'enterprise'].includes(tier)) {
      return res.status(400).json({ error: 'Tier must be: developer, pro, or enterprise' });
    }

    const rawKey = generateApiKey(tier);
    const keyHash = hashKey(rawKey);

    // The key data to store (you'll add this to BRMSTE_API_KEYS env var)
    const keyData = {
      customer,
      tier,
      created: new Date().toISOString(),
      active: true,
      tokensUsed: 0,
    };

    auditLog({ event: 'KEY_GENERATED', customer, tier, keyHash: keyHash.substring(0, 8) });

    return res.status(201).json({
      message: 'API key generated successfully',
      key: rawKey,
      keyHash,
      keyData,
      instructions: [
        'IMPORTANT: This key is shown ONCE. Store it securely.',
        'The customer uses it as: Authorization: Bearer ' + rawKey,
        'Add to BRMSTE_API_KEYS env var in Vercel:',
        `  "${keyHash}": ${JSON.stringify(keyData)}`,
      ],
    });

  } else if (req.method === 'GET') {
    // ── LIST KEYS ──
    let store;
    try {
      store = JSON.parse(process.env.BRMSTE_API_KEYS || '{}');
    } catch {
      store = {};
    }

    const keys = Object.entries(store).map(([hash, data]) => ({
      keyHash: hash.substring(0, 12) + '...',
      customer: data.customer,
      tier: data.tier,
      active: data.active,
      created: data.created,
      tokensUsed: data.tokensUsed || 0,
    }));

    return res.status(200).json({ keys, count: keys.length });

  } else if (req.method === 'DELETE') {
    // ── REVOKE KEY ──
    const { keyHash } = req.body || {};
    if (!keyHash) return res.status(400).json({ error: 'keyHash required' });

    auditLog({ event: 'KEY_REVOKED', keyHash: keyHash.substring(0, 8) });

    return res.status(200).json({
      message: 'Key marked for revocation',
      instructions: [
        'Update BRMSTE_API_KEYS in Vercel:',
        `Set "active": false for hash starting with "${keyHash.substring(0, 12)}"`,
      ],
    });

  } else {
    return res.status(405).json({ error: 'Method not allowed', allowed: ['GET', 'POST', 'DELETE'] });
  }
};
