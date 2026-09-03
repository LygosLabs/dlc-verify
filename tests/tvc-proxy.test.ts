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

function createProof(
  challenge: string,
  result: unknown,
  request: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signingPoint = publicKey
    .export({ format: 'der', type: 'spki' })
    .subarray(-65);
  const proofPayload = JSON.stringify({
    proofType: 'APP_PROOF_TYPE_LYGOS_DLC_VERIFICATION',
    schemaVersion: '1',
    verifierVersion: '0.2.0',
    requestDigest: handler.computeRequestDigest(request),
    challenge,
    result,
    ...overrides,
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
    const policy = {
      lenderRole: 'offerer',
      network: 'regtest',
      expectedOraclePubkey: 'dd',
      expectedLenderFundingPubkey: `02${'11'.repeat(32)}`,
      expectedLenderPayoutAddress: 'bcrt1qlender',
      expectedTotalCollateralSats: '20000',
      oracleEvent: { expectedEventId: 'loan-matured-123' },
      expectedCetLocktime: 1_700_000_000,
      expectedRefundLocktime: 1_700_003_600,
      expectedLenderOutcomes: [{ outcome: 'repaid', lenderPayoutSats: '20000' }],
    };
    const tvcRequest = {
      offer: 'aa',
      accept: 'bb',
      signHex: 'cc',
      network: 'regtest',
      policy,
      challenge,
    };
    const proof = createProof(challenge, policyResult, tvcRequest);
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
        network: 'regtest',
        challenge,
        policy,
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
      policy,
    });
  });

  it('maps the legacy expected oracle field to a partial TVC policy', async () => {
    const challenge = 'legacy-oracle-policy';
    const result = { verdict: 'incomplete', verification: { verificationStatus: 'pass' } };
    const proof = createProof(challenge, result, {
      offer: 'aa',
      accept: 'bb',
      policy: { expectedOraclePubkey: 'dd' },
      challenge,
    });
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ result, proof }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const res = mockResponse();

    await handler(
      {
        method: 'POST',
        body: {
          offer: 'aa',
          accept: 'bb',
          expectedOraclePubkey: 'dd',
          challenge,
        },
      },
      res,
    );

    expect(res.statusCode).toBe(200);
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(String(init?.body)).policy).toEqual({ expectedOraclePubkey: 'dd' });
  });

  it('rejects a non-object policy before calling TVC', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = mockResponse();

    await handler(
      {
        method: 'POST',
        body: { offer: 'aa', accept: 'bb', policy: [], challenge: 'invalid-policy' },
      },
      res,
    );

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe('Policy must be a JSON object');
    expect(fetchMock).not.toHaveBeenCalled();
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
    const signedResult = { verdict: 'fail', verification: { verificationStatus: 'fail' } };
    const request = { offer: 'aa', accept: 'bb', challenge };
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            result: { verdict: 'pass' },
            proof: createProof(challenge, signedResult, request),
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
    expect(JSON.parse(res.body).result).toEqual(signedResult.verification);
    expect(JSON.parse(res.body).policyResult).toEqual(signedResult);
  });

  it('rejects an invalid App Proof signature', async () => {
    const challenge = 'signature-check';
    const proof = createProof(challenge, {
      verdict: 'pass',
      verification: { verificationStatus: 'pass' },
    }, {
      offer: 'aa',
      accept: 'bb',
      challenge,
    });
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

  it('rejects a valid proof bound to a different policy request', async () => {
    const challenge = 'request-binding-check';
    const proof = createProof(challenge, {
      verdict: 'pass',
      verification: { verificationStatus: 'pass' },
    }, {
      offer: 'aa',
      accept: 'bb',
      policy: { network: 'mainnet' },
      challenge,
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ result: { verdict: 'pass' }, proof }), { status: 200 }),
      ),
    );
    const res = mockResponse();

    await handler(
      {
        method: 'POST',
        body: { offer: 'aa', accept: 'bb', policy: { network: 'regtest' }, challenge },
      },
      res,
    );

    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body).error).toContain('not bound to this verification request');
  });

  it('rejects signed payloads from an unexpected verifier version', async () => {
    const challenge = 'version-check';
    const request = { offer: 'aa', accept: 'bb', challenge };
    const result = { verdict: 'pass', verification: { verificationStatus: 'pass' } };
    const proof = createProof(challenge, result, request, { verifierVersion: '0.1.0' });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ result, proof }), { status: 200 })),
    );
    const res = mockResponse();

    await handler({ method: 'POST', body: request }, res);

    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body).error).toContain('unexpected verifier version');
  });

  it('rejects a signed payload without a request digest', async () => {
    const challenge = 'missing-digest-check';
    const request = { offer: 'aa', accept: 'bb', challenge };
    const result = { verdict: 'pass', verification: { verificationStatus: 'pass' } };
    const proof = createProof(challenge, result, request, { requestDigest: undefined });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ result, proof }), { status: 200 })),
    );
    const res = mockResponse();

    await handler({ method: 'POST', body: request }, res);

    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body).error).toContain('not bound to this verification request');
  });

  it('rejects a signed policy result without nested DLC verification output', async () => {
    const challenge = 'nested-result-check';
    const request = { offer: 'aa', accept: 'bb', challenge };
    const result = { verdict: 'pass' };
    const proof = createProof(challenge, result, request);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ result, proof }), { status: 200 })),
    );
    const res = mockResponse();

    await handler({ method: 'POST', body: request }, res);

    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body).error).toContain('unexpected schema');
  });

  it('binds the App Proof to every verification input and policy field', async () => {
    const challenge = 'all-input-binding-check';
    const policy = {
      lenderRole: 'offerer',
      network: 'regtest',
      expectedOraclePubkey: '11'.repeat(32),
      expectedLenderFundingPubkey: `02${'22'.repeat(32)}`,
      expectedLenderPayoutAddress: 'bcrt1qlender',
      expectedTotalCollateralSats: '20000',
      oracleEvent: {
        eventIdPreimage: {
          eventType: 'loan-matured',
          loanId: 'loan-123',
          repaymentAddress: 'bcrt1qrepayment',
          repaymentAmount: '20000',
        },
      },
      expectedCetLocktime: 1_700_000_000,
      expectedRefundLocktime: 1_700_003_600,
      expectedLenderOutcomes: [{ outcome: 'repaid', lenderPayoutSats: '20000' }],
    };
    const baseRequest = {
      offer: 'aa',
      accept: 'bb',
      signHex: 'cc',
      network: 'regtest',
      policy,
      challenge,
    };
    const result = { verdict: 'pass', verification: { verificationStatus: 'pass' } };
    const proof = createProof(challenge, result, baseRequest);
    const mutations = [
      { ...baseRequest, offer: 'ab' },
      { ...baseRequest, accept: 'bc' },
      { ...baseRequest, signHex: 'cd' },
      { ...baseRequest, network: 'testnet' },
      { ...baseRequest, policy: { ...policy, lenderRole: 'accepter' } },
      { ...baseRequest, policy: { ...policy, network: 'testnet' } },
      { ...baseRequest, policy: { ...policy, expectedOraclePubkey: '33'.repeat(32) } },
      { ...baseRequest, policy: { ...policy, expectedLenderFundingPubkey: `03${'22'.repeat(32)}` } },
      { ...baseRequest, policy: { ...policy, expectedLenderPayoutAddress: 'bcrt1qother' } },
      { ...baseRequest, policy: { ...policy, expectedTotalCollateralSats: '20001' } },
      {
        ...baseRequest,
        policy: {
          ...policy,
          oracleEvent: {
            eventIdPreimage: { ...policy.oracleEvent.eventIdPreimage, loanId: 'loan-124' },
          },
        },
      },
      { ...baseRequest, policy: { ...policy, expectedCetLocktime: 1_700_000_001 } },
      { ...baseRequest, policy: { ...policy, expectedRefundLocktime: 1_700_003_601 } },
      {
        ...baseRequest,
        policy: {
          ...policy,
          expectedLenderOutcomes: [{ outcome: 'repaid', lenderPayoutSats: '19999' }],
        },
      },
    ];

    for (const mutatedRequest of mutations) {
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => new Response(JSON.stringify({ result, proof }), { status: 200 })),
      );
      const res = mockResponse();
      await handler({ method: 'POST', body: mutatedRequest }, res);
      expect(res.statusCode).toBe(502);
      expect(JSON.parse(res.body).error).toContain('not bound to this verification request');
    }
  });

  it('rejects networks unsupported by the deployed TVC verifier', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const res = mockResponse();

    await handler(
      { method: 'POST', body: { offer: 'aa', accept: 'bb', network: 'signet', challenge: 'network-check' } },
      res,
    );

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toBe('Unsupported Bitcoin network');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('matches the Rust qos_json request digest golden', () => {
    const fixture = require('../examples/sample.json');
    expect(
      handler.computeRequestDigest({
        offer: fixture.offer,
        accept: fixture.accept,
        network: 'regtest',
        policy: { network: 'regtest' },
        challenge: 'vercel-proxy-pr9-policy-digest-canary-2026-09-02',
      }),
    ).toBe('4e19a4f85dd4e4614a531047768cf56486a0bd8ef41abda866507cbad1acffde');
  });
});
