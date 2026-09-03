import { generateKeyPairSync, sign } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

const handler = require('../api/verify.js');

function mockResponse() {
  const headers = new Map<string, string>();
  return {
    statusCode: 0,
    body: '',
    headers,
    setHeader(name: string, value: string) {
      headers.set(name.toLowerCase(), value);
    },
    end(body: string) {
      this.body = body;
    },
  };
}

function createProof(challenge: string, result: unknown) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signingPoint = publicKey
    .export({ format: 'der', type: 'spki' })
    .subarray(-65);
  const proofPayload = JSON.stringify({
    proofType: 'APP_PROOF_TYPE_LYGOS_DLC_VERIFICATION',
    schemaVersion: '1',
    verifierVersion: '0.2.0',
    challenge,
    result,
  });
  return {
    scheme: 'SIGNATURE_SCHEME_EPHEMERAL_KEY_P256',
    publicKey: Buffer.concat([signingPoint, signingPoint]).toString('hex'),
    signature: sign('sha256', Buffer.from(proofPayload), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
    proofPayload,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.TVC_VERIFIER_URL;
});

describe('Vercel to Turnkey TVC proxy', () => {
  it('maps the existing UI request to the proof-bearing TVC endpoint', async () => {
    const challenge = 'browser-generated-challenge';
    const policyResult = {
      verdict: 'pass',
      verification: { fundTxId: 'funding-transaction', verificationStatus: 'pass' },
    };
    const proof = createProof(challenge, policyResult);
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ result: policyResult, proof }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const req = {
      method: 'POST',
      body: {
        offer: 'aa',
        accept: 'bb',
        signHex: 'cc',
        expectedOraclePubkey: 'dd',
        network: 'regtest',
        challenge,
      },
    };
    const res = mockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(res.headers.get('x-lygos-verifier-backend')).toBe('turnkey-tvc');
    const body = JSON.parse(res.body);
    expect(body.result).toEqual(policyResult.verification);
    expect(body.proof).toEqual(proof);
    expect(body.execution.challenge).toBe(challenge);
    expect(body.execution.environment).toBe('turnkey-verifiable-cloud');

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe(
      'https://app-bd66858d-2584-4e34-ae43-564de32aeccb.app.turnkey.cloud/v1/verify',
    );
    expect(JSON.parse(String(init?.body))).toEqual({
      offer: 'aa',
      accept: 'bb',
      signHex: 'cc',
      network: 'regtest',
      challenge,
      policy: { expectedOraclePubkey: 'dd' },
    });
  });

  it('requires a browser-generated challenge before calling TVC', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = mockResponse();

    await handler({ method: 'POST', body: { offer: 'aa', accept: 'bb' } }, res);

    expect(res.statusCode).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('uses the signed result instead of a divergent unsigned outer result', async () => {
    const challenge = 'one-time-challenge';
    const signedResult = { verdict: 'fail' };
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            result: { verdict: 'pass' },
            proof: createProof(challenge, signedResult),
          }),
          { status: 200 },
        ),
      ),
    );
    const res = mockResponse();

    await handler(
      { method: 'POST', body: { offer: 'aa', accept: 'bb', challenge } },
      res,
    );

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).result).toEqual(signedResult);
  });

  it('rejects an invalid App Proof signature', async () => {
    const challenge = 'signature-check';
    const proof = createProof(challenge, { verdict: 'pass' });
    proof.signature = `${proof.signature.startsWith('00') ? '01' : '00'}${proof.signature.slice(2)}`;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ result: { verdict: 'pass' }, proof }), { status: 200 }),
      ),
    );
    const res = mockResponse();

    await handler(
      { method: 'POST', body: { offer: 'aa', accept: 'bb', challenge } },
      res,
    );

    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body).error).toContain('signature is invalid');
  });
});
