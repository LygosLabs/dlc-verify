const { createPublicKey, verify } = require('node:crypto');

const DEFAULT_TVC_VERIFIER_URL =
  'https://app-bd66858d-2584-4e34-ae43-564de32aeccb.app.turnkey.cloud';
const MAX_REQUEST_BYTES = 7 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 28_000;
const NETWORKS = new Set(['mainnet', 'testnet', 'testnet4', 'regtest', 'signet']);
const P256_SPKI_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex',
);

async function readJson(req, maxBytes = MAX_REQUEST_BYTES) {
  if (req.body) {
    const serialized = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    if (Buffer.byteLength(serialized) > maxBytes) throw new Error('Request body too large');
    return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body;
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

function getTvcEndpoint() {
  const configured = process.env.TVC_VERIFIER_URL?.trim() || DEFAULT_TVC_VERIFIER_URL;
  const base = new URL(configured);
  if (
    base.protocol !== 'https:' ||
    !base.hostname.endsWith('.app.turnkey.cloud') ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  ) {
    throw new Error('TVC_VERIFIER_URL must be an HTTPS Turnkey TVC application origin');
  }
  return new URL('/v1/verify', base);
}

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-lygos-verifier-backend', 'turnkey-tvc');
  res.end(JSON.stringify(body));
}

function validateProofEnvelope(envelope, challenge) {
  if (!envelope || typeof envelope !== 'object' || !envelope.result || !envelope.proof) {
    throw new Error('Turnkey TVC returned an invalid proof envelope');
  }
  if (typeof envelope.proof.proofPayload !== 'string') {
    throw new Error('Turnkey TVC response is missing its signed proof payload');
  }
  verifyAppProofSignature(envelope.proof);

  let signedPayload;
  try {
    signedPayload = JSON.parse(envelope.proof.proofPayload);
  } catch {
    throw new Error('Turnkey TVC returned a malformed signed proof payload');
  }
  if (signedPayload.challenge !== challenge) {
    throw new Error('Turnkey TVC proof challenge does not match this request');
  }
  if (
    signedPayload.proofType !== 'APP_PROOF_TYPE_LYGOS_DLC_VERIFICATION' ||
    signedPayload.schemaVersion !== '1' ||
    !signedPayload.result
  ) {
    throw new Error('Turnkey TVC signed proof payload has an unexpected schema');
  }
  return signedPayload;
}

function verifyAppProofSignature(proof) {
  if (proof.scheme !== 'SIGNATURE_SCHEME_EPHEMERAL_KEY_P256') {
    throw new Error('Turnkey TVC App Proof uses an unexpected signature scheme');
  }
  if (!/^[0-9a-f]{260}$/i.test(proof.publicKey || '')) {
    throw new Error('Turnkey TVC App Proof has an invalid composite public key');
  }
  if (!/^[0-9a-f]{128}$/i.test(proof.signature || '')) {
    throw new Error('Turnkey TVC App Proof has an invalid signature');
  }

  const compositeKey = Buffer.from(proof.publicKey, 'hex');
  const signingKey = compositeKey.subarray(65);
  const publicKey = createPublicKey({
    key: Buffer.concat([P256_SPKI_PREFIX, signingKey]),
    format: 'der',
    type: 'spki',
  });
  const valid = verify(
    'sha256',
    Buffer.from(proof.proofPayload, 'utf8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(proof.signature, 'hex'),
  );
  if (!valid) throw new Error('Turnkey TVC App Proof signature is invalid');
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
    const expectedOraclePubkey = cleanHex(body.expectedOraclePubkey);
    const challenge = typeof body.challenge === 'string' ? body.challenge.trim() : '';
    const network = typeof body.network === 'string' ? body.network.trim().toLowerCase() : '';

    if (!offer || !accept) {
      sendJson(res, 400, { error: 'Missing offer or accept hex' });
      return;
    }
    if (!challenge || challenge.length > 256) {
      sendJson(res, 400, { error: 'A unique challenge of at most 256 characters is required' });
      return;
    }
    if (network && !NETWORKS.has(network)) {
      sendJson(res, 400, { error: 'Unsupported Bitcoin network' });
      return;
    }

    const tvcRequest = { offer, accept, challenge };
    if (signHex) tvcRequest.signHex = signHex;
    if (network) tvcRequest.network = network;
    if (expectedOraclePubkey) tvcRequest.policy = { expectedOraclePubkey };

    const endpoint = getTvcEndpoint();
    const upstream = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(tvcRequest),
      redirect: 'error',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    const responseText = await upstream.text();
    let envelope;
    try {
      envelope = JSON.parse(responseText);
    } catch {
      sendJson(res, 502, { error: 'Turnkey TVC returned a non-JSON response' });
      return;
    }
    if (!upstream.ok) {
      sendJson(res, upstream.status, envelope);
      return;
    }

    const signedPayload = validateProofEnvelope(envelope, challenge);
    sendJson(res, 200, {
      result: signedPayload.result.verification || signedPayload.result,
      policyResult: signedPayload.result,
      proof: envelope.proof,
      execution: {
        environment: 'turnkey-verifiable-cloud',
        endpointHost: endpoint.hostname,
        challenge,
        signedVerdict: signedPayload.result.verdict,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const status = message.includes('too large')
      ? 413
      : error?.name === 'TimeoutError' || error?.name === 'AbortError'
        ? 504
        : 502;
    sendJson(res, status, { error: message });
  }
};

module.exports.validateProofEnvelope = validateProofEnvelope;
