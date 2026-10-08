import * as bitcoin from 'bitcoinjs-lib';
import { describe, expect, it } from 'vitest';
import { executeCet, verifyDlc } from '../src/verify';
import {
  SAMPLE_EVENT_MATURITY,
  attestationHex,
  bogusSignature,
  cetWitnessValid,
  makeContract,
  payoutAddress,
  txOutputs,
} from './helpers/synthetic-dlc';

const regtest = bitcoin.networks.regtest;
const verifyAll = (c: ReturnType<typeof makeContract>) =>
  verifyDlc(c.hex.offer, c.hex.accept, { signHex: c.hex.sign, network: 'regtest' });

const LOAN_OUTCOMES = [
  { outcome: 'not-paid', localPayout: 20000 },
  { outcome: 'repaid', localPayout: 20000 },
  { outcome: 'liquidated-by-maturation-date', localPayout: 0 },
  { outcome: 'liquidated-by-price-threshold', localPayout: 0 },
];

describe('Synthetic contracts', () => {
  it('a freshly signed contract passes every check', async () => {
    const result = await verifyAll(makeContract());
    expect(result.verificationStatus).toBe('pass');
    expect(result.verificationFailures).toEqual([]);
    expect(result.contractFlags).toBe(0);
    expect(result.refundMode).toBe('each-party');
    expect(result.oracleEventMatchesContract).toBe(true);
    expect(result.eventMaturityEpoch).toBe(SAMPLE_EVENT_MATURITY);
    expect(result.locktimesValid).toBe(true);
    expect(result.canonicalEncoding).toBe(true);
  });
});

describe('Oracle event must describe the contract outcomes', () => {
  it('fails when a contract outcome string is not in the signed event', async () => {
    const contract = LOAN_OUTCOMES.map((o) => (o.outcome === 'repaid' ? { ...o, outcome: 'repaid ' } : o));
    const c = makeContract({ contractOutcomes: contract, announcedOutcomes: LOAN_OUTCOMES.map((o) => o.outcome) });
    const result = await verifyAll(c);
    // Every signature is genuine; only the oracle's commitment is wrong.
    expect(result.adaptorValid).toBe(true);
    expect(result.signAdaptorValid).toBe(true);
    expect(result.oracleEventMatchesContract).toBe(false);
    expect(result.oracleEventError).toContain('"repaid "');
    expect(result.verificationFailures).toContain('oracle-event-outcomes-mismatch-or-unavailable');
    expect(result.verificationStatus).toBe('fail');
  });

  it('fails when the signed event has a different number of outcomes', async () => {
    const c = makeContract({ announcedOutcomes: LOAN_OUTCOMES.slice(0, 3).map((o) => o.outcome) });
    const result = await verifyAll(c);
    expect(result.oracleEventError).toMatch(/4 outcomes, the signed announcement has 3/);
    expect(result.verificationStatus).toBe('fail');
  });

  it('fails when contract outcomes are duplicated', async () => {
    const c = makeContract({
      contractOutcomes: [...LOAN_OUTCOMES.slice(0, 3), { outcome: 'repaid', localPayout: 0 }],
      announcedOutcomes: LOAN_OUTCOMES.map((o) => o.outcome),
    });
    const result = await verifyAll(c);
    expect(result.oracleEventError).toMatch(/not unique/);
    expect(result.verificationStatus).toBe('fail');
  });
});

describe('Contract flags', () => {
  it('verifies a refund-to-accepter contract and reports the refund mode', async () => {
    const c = makeContract({ contractFlags: 1 });
    const result = await verifyAll(c);
    expect(result.verificationStatus).toBe('pass');
    expect(result.contractFlags).toBe(1);
    expect(result.refundMode).toBe('accepter');
    const accepter = payoutAddress(c.accept, regtest);
    expect(result.refundOutputs.map((o) => o.address)).toEqual([accepter]);
    expect(txOutputs(Buffer.from(c.built.txs.refund.rawBytes), regtest).map((o) => o.address)).toEqual([accepter]);
  });

  it('fails when the flags byte does not match the signed refund', async () => {
    const c = makeContract({ contractFlags: 1, signFlags: 0 });
    const result = await verifyAll(c);
    expect(result.refundSigValid).toBe(false);
    expect(result.signRefundSigValid).toBe(false);
    expect(result.verificationStatus).toBe('fail');
  });

  it('rejects unknown flag bits instead of reconstructing with them', async () => {
    const c = makeContract({ contractFlags: 0x02, signFlags: 0 });
    const result = await verifyAll(c);
    expect(result.contractFlagsError).toMatch(/unsupported contract_flags 0x02/);
    expect(result.adaptorSigVerificationAvailable).toBe(false);
    expect(result.verificationFailures).toContain('unsupported-contract-flags');
    expect(result.verificationStatus).toBe('fail');
  });
});

describe('Locktimes', () => {
  const maturity = SAMPLE_EVENT_MATURITY;

  it('fails when the refund locktime is not after oracle maturity', async () => {
    const c = makeContract({ cetLocktime: maturity - 86400, refundLocktime: maturity });
    const result = await verifyAll(c);
    expect(result.locktimeError).toMatch(/refundLocktime .* is not after oracle event maturity/);
    expect(result.verificationFailures).toContain('locktimes-invalid-or-unavailable');
    expect(result.verificationStatus).toBe('fail');
  });

  it('fails when the CET locktime is after oracle maturity', async () => {
    const c = makeContract({ cetLocktime: maturity + 1, refundLocktime: maturity + 2 });
    const result = await verifyAll(c);
    expect(result.locktimeError).toMatch(/cetLocktime .* is after oracle event maturity/);
    expect(result.verificationStatus).toBe('fail');
  });

  it('fails when the refund locktime is zero', async () => {
    const c = makeContract({ cetLocktime: maturity + 86400, refundLocktime: 0 });
    const result = await verifyAll(c);
    expect(result.locktimeError).toMatch(/not in the same units/);
    expect(result.verificationStatus).toBe('fail');
  });

  it('fails when locktimes are block heights', async () => {
    const c = makeContract({ cetLocktime: 1_000_000, refundLocktime: 1_000_100 });
    const result = await verifyAll(c);
    expect(result.locktimeError).toMatch(/block-height locktimes/);
    expect(result.verificationStatus).toBe('fail');
  });
});

describe('Message encoding', () => {
  it('fails when an offer carries trailing TLV bytes', async () => {
    const c = makeContract();
    const padded = `${c.hex.offer}fdffff0100`;
    const result = await verifyDlc(padded, c.hex.accept, { signHex: c.hex.sign, network: 'regtest' });
    expect(result.canonicalEncoding).toBe(false);
    expect(result.encodingError).toMatch(/offer carries 1 unknown TLV record/);
    expect(result.verificationFailures).toContain('non-canonical-message-encoding');
    expect(result.verificationStatus).toBe('fail');
  });
});

describe('CET execution', () => {
  it('builds a settlement whose witness verifies from a genuine attestation', async () => {
    const c = makeContract();
    const out = await executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(c.oracle, c.eventId, 'repaid'));
    expect(out.outcome).toBe('repaid');
    expect(cetWitnessValid(out.cetHex, c.built, c.offerer.pk, c.accepter.pk)).toBe(true);
  });

  it('honours the refund-to-accepter flag when rebuilding the CETs', async () => {
    const c = makeContract({ contractFlags: 1 });
    const out = await executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(c.oracle, c.eventId, 'repaid'));
    expect(cetWitnessValid(out.cetHex, c.built, c.offerer.pk, c.accepter.pk)).toBe(true);
  });

  it('rejects an attestation whose signature does not verify', async () => {
    const c = makeContract();
    await expect(
      executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(c.oracle, c.eventId, 'repaid', bogusSignature())),
    ).rejects.toThrow(/Attestation (signature is invalid|nonce does not match)/);
  });

  it('rejects an attestation under a nonce the oracle never announced', async () => {
    const c = makeContract();
    const sig = c.oracle.attestWithFreshNonce('repaid');
    await expect(executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(c.oracle, c.eventId, 'repaid', sig))).rejects.toThrow(
      /nonce does not match the announced nonce/,
    );
  });

  it('rejects an attestation from a different oracle', async () => {
    const c = makeContract();
    const other = makeContract();
    await expect(
      executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(other.oracle, c.eventId, 'repaid')),
    ).rejects.toThrow(/oracle public key does not match/);
  });

  it('rejects an attested outcome the contract does not have', async () => {
    const c = makeContract();
    await expect(executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(c.oracle, c.eventId, 'paid'))).rejects.toThrow(
      /not found in contract outcomes/,
    );
  });

  it('refuses to build a settlement for a transcript that does not verify', async () => {
    const contract = LOAN_OUTCOMES.map((o) => (o.outcome === 'repaid' ? { ...o, outcome: 'repaid ' } : o));
    const c = makeContract({ contractOutcomes: contract, announcedOutcomes: LOAN_OUTCOMES.map((o) => o.outcome) });
    await expect(
      executeCet(c.hex.offer, c.hex.accept, c.hex.sign, attestationHex(c.oracle, c.eventId, 'liquidated-by-price-threshold')),
    ).rejects.toThrow(/does not verify: .*oracle-event-outcomes-mismatch/);
  });
});
