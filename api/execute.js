const { executeCet } = require('../dist/verify.js');

async function readJson(req, maxBytes = 10_000_000) {
  if (req.body) {
    if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
    return req.body;
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Error('Request body too large');
    chunks.push(chunk);
  }

  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function cleanHex(value) {
  if (typeof value !== 'string') return null;
  const hex = value.trim().replace(/^0x/i, '').replace(/\s+/g, '');
  return hex || null;
}

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'Method not allowed' });
    return;
  }

  try {
    const body = await readJson(req);
    const offer = cleanHex(body.offer);
    const accept = cleanHex(body.accept);
    const signHex = cleanHex(body.signHex);
    const attestationHex = cleanHex(body.attestationHex);

    if (!offer || !accept || !signHex || !attestationHex) {
      sendJson(res, 400, {
        error: 'Missing required fields: offer, accept, signHex, attestationHex',
      });
      return;
    }

    const result = await executeCet(offer, accept, signHex, attestationHex);
    sendJson(res, 200, result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    sendJson(res, message.includes('too large') ? 413 : 500, { error: message });
  }
};
