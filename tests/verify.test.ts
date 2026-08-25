import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect, beforeAll } from 'vitest';
import { deriveLygosOracleEventId, type DlcVerificationPolicy, verifyDlcAgainstPolicy } from '../src/policy';
import { verifyDlc } from '../src/verify';
import {
  loadSampleData,
  deserializeOffer,
  deserializeAccept,
  serializeOffer,
  serializeAccept,
  modifyCetLocktime,
  modifyOfferCollateral,
  modifyAcceptCollateral,
  modifyOfferFundingPubkey,
  modifyAcceptFundingPubkey,
  getOraclePubkey,
  generateRandomPubkey,
  generateRandomXOnlyPubkey,
  corruptAdaptorSignatures,
  corruptAcceptRefundSignature,
  corruptSignAdaptorSignatures,
  corruptSignRefundSignature,
} from './helpers/dlc-builder';

describe('DLC Verification', () => {
  let sampleOffer: string;
  let sampleAccept: string;

  beforeAll(() => {
    const sample = loadSampleData();
    sampleOffer = sample.offer;
    sampleAccept = sample.accept;
  });

  describe('Baseline - Valid Messages', () => {
    it('should pass verification for valid offer/accept pair', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.error).toBeNull();
      expect(result.contractType).toBe('Enumerated');
      expect(result.totalCollateral).not.toBeNull();
      expect(result.offerCollateral).not.toBeNull();
      expect(result.acceptCollateral).not.toBeNull();
      expect(result.oracleSigValid).toBe(true);
    });

    it('should successfully verify CET adaptor signatures', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.adaptorSigVerificationAvailable).toBe(true);
      expect(result.adaptorValid).toBe(true);
      expect(result.adaptorValidCount).toBeGreaterThan(0);
      expect(result.adaptorValidCount).toBe(result.adaptorTotalCount);
      expect(result.adaptorError).toBeNull();
    });

    it('should extract correct contract parameters', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      // Verify outcomes are extracted
      expect(result.outcomes.length).toBeGreaterThan(0);

      // Verify funding pubkeys are extracted
      expect(result.offererFundingPubkey).toBeTruthy();
      expect(result.accepterFundingPubkey).toBeTruthy();

      // Verify funding address is reconstructed
      expect(result.fundingAddress).toBeTruthy();
      expect(result.witnessScript).toBeTruthy();

      // Verify locktimes are extracted
      expect(result.cetLocktime).not.toBeNull();
      expect(result.refundLocktime).not.toBeNull();
    });
  });

  describe('Tampered Messages - Adaptor Verification Should Fail', () => {
    it('should fail adaptor verification when cetLocktime is modified', async () => {
      // Modify the CET locktime to a different value
      const originalOffer = deserializeOffer(sampleOffer);
      const originalLocktime = originalOffer.cetLocktime;
      const modifiedLocktime = originalLocktime + 100;

      const modifiedOfferHex = modifyCetLocktime(sampleOffer, modifiedLocktime);
      const result = await verifyDlc(modifiedOfferHex, sampleAccept);

      // The cetLocktime should reflect the modified value
      expect(result.cetLocktime).toBe(modifiedLocktime);

      // Adaptor signatures should fail because the CETs are reconstructed differently
      expect(result.adaptorValid).toBe(false);
    });

    it('should fail adaptor verification when offer collateral is modified', async () => {
      const originalOffer = deserializeOffer(sampleOffer);
      const originalCollateral = originalOffer.offerCollateral;
      // Slightly modify the collateral
      const modifiedCollateral = originalCollateral + 1000n;

      const modifiedOfferHex = modifyOfferCollateral(sampleOffer, modifiedCollateral);
      const result = await verifyDlc(modifiedOfferHex, sampleAccept);

      // The offer collateral should reflect the modified value
      expect(result.offerCollateral).toBe(modifiedCollateral.toString());

      // Adaptor signatures should either fail (false) or verification not be available (null)
      // because modifying collateral changes the CET outputs
      expect(result.adaptorValid !== true).toBe(true);
    });

    it('should fail adaptor verification when offerer funding pubkey is modified', async () => {
      const randomPubkey = generateRandomPubkey();
      const modifiedOfferHex = modifyOfferFundingPubkey(sampleOffer, randomPubkey);
      const result = await verifyDlc(modifiedOfferHex, sampleAccept);

      // The funding pubkey should reflect the modified value
      expect(result.offererFundingPubkey).toBe(randomPubkey.toString('hex'));

      // Adaptor signatures should either fail (false) or verification not be available (null)
      // because the funding script changed
      expect(result.adaptorValid !== true).toBe(true);
    });

    it('should fail adaptor verification when accepter funding pubkey is modified', async () => {
      const randomPubkey = generateRandomPubkey();
      const modifiedAcceptHex = modifyAcceptFundingPubkey(sampleAccept, randomPubkey);
      const result = await verifyDlc(sampleOffer, modifiedAcceptHex);

      // The funding pubkey should reflect the modified value
      expect(result.accepterFundingPubkey).toBe(randomPubkey.toString('hex'));

      // Adaptor signatures should either fail (false) or verification not be available (null)
      // because the funding script changed
      expect(result.adaptorValid !== true).toBe(true);
    });

    it('should fail adaptor verification when adaptor signatures are corrupted', async () => {
      const corruptedAcceptHex = corruptAdaptorSignatures(sampleAccept);
      const result = await verifyDlc(sampleOffer, corruptedAcceptHex);

      // Adaptor signatures should fail
      expect(result.adaptorValid).toBe(false);
    });
  });

  describe('Oracle Pubkey Validation', () => {
    it('should extract oracle pubkey from offer', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.extractedOraclePubkey).toBeTruthy();
      expect(result.extractedOraclePubkey?.length).toBe(64); // 32 bytes = 64 hex chars
      expect(result.oraclePubkeySource).toBe('derived');
    });

    it('should match when expected oracle pubkey equals extracted', async () => {
      const extractedPubkey = getOraclePubkey(sampleOffer);
      expect(extractedPubkey).toBeTruthy();

      const result = await verifyDlc(sampleOffer, sampleAccept, {
        expectedOraclePubkey: extractedPubkey!,
      });

      expect(result.oraclePubkeyMatchesExpected).toBe(true);
      expect(result.oraclePubkeySource).toBe('provided');
      expect(result.expectedOraclePubkey).toBe(extractedPubkey);
    });

    it('should detect mismatch when expected oracle pubkey differs', async () => {
      const wrongPubkey = generateRandomXOnlyPubkey();

      const result = await verifyDlc(sampleOffer, sampleAccept, {
        expectedOraclePubkey: wrongPubkey,
      });

      expect(result.oraclePubkeyMatchesExpected).toBe(false);
      expect(result.oraclePubkeySource).toBe('provided');
      expect(result.expectedOraclePubkey).toBe(wrongPubkey);
      expect(result.extractedOraclePubkey).not.toBe(wrongPubkey);
    });

    it('should handle oracle pubkey with 0x prefix', async () => {
      const extractedPubkey = getOraclePubkey(sampleOffer);
      expect(extractedPubkey).toBeTruthy();

      const result = await verifyDlc(sampleOffer, sampleAccept, {
        expectedOraclePubkey: `0x${extractedPubkey}`,
      });

      expect(result.oraclePubkeyMatchesExpected).toBe(true);
      expect(result.expectedOraclePubkey).toBe(extractedPubkey); // Should be normalized
    });

    it('should handle oracle pubkey with uppercase hex', async () => {
      const extractedPubkey = getOraclePubkey(sampleOffer);
      expect(extractedPubkey).toBeTruthy();

      const result = await verifyDlc(sampleOffer, sampleAccept, {
        expectedOraclePubkey: extractedPubkey!.toUpperCase(),
      });

      expect(result.oraclePubkeyMatchesExpected).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should return error for invalid offer hex', async () => {
      const result = await verifyDlc('invalidhex', sampleAccept);
      expect(result.error).toBeTruthy();
    });

    it('should return error for invalid accept hex', async () => {
      const result = await verifyDlc(sampleOffer, 'invalidhex');
      expect(result.error).toBeTruthy();
    });

    it('should return error for empty offer', async () => {
      const result = await verifyDlc('', sampleAccept);
      expect(result.error).toBeTruthy();
    });

    it('should return error for truncated offer', async () => {
      const truncated = sampleOffer.slice(0, 100);
      const result = await verifyDlc(truncated, sampleAccept);
      expect(result.error).toBeTruthy();
    });
  });

  describe('Contract Parameters', () => {
    it('should correctly parse enumerated contract outcomes', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.contractType).toBe('Enumerated');
      expect(result.outcomes.length).toBeGreaterThan(0);

      // Each outcome should have label, offererSats, and accepterSats
      for (const outcome of result.outcomes) {
        expect(outcome.label).toBeTruthy();
        expect(outcome.offererSats).toBeTruthy();
        expect(outcome.accepterSats).toBeTruthy();
      }
    });

    it('should verify collateral sum equals total', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      const total = BigInt(result.totalCollateral!);
      const offer = BigInt(result.offerCollateral!);
      const accept = BigInt(result.acceptCollateral!);

      expect(offer + accept).toBe(total);
    });

    it('should verify oracle announcement signature', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.oracleSigValid).toBe(true);
      expect(result.oracleSigError).toBeNull();
    });

    it('should extract oracle event ID', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.oracleEventId).toBeTruthy();
    });
  });

  describe('Complete DlcSign and refund verification', () => {
    const signedSample = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, '../examples/testnet-loan-118c9fc9.json'), 'utf8'),
    ) as { offer: string; accept: string; sign: string; oraclePubkey: string };

    it('cryptographically verifies both adaptor sets and both refund signatures', async () => {
      const result = await verifyDlc(signedSample.offer, signedSample.accept, {
        signHex: signedSample.sign,
        expectedOraclePubkey: signedSample.oraclePubkey,
        network: 'regtest',
      });

      expect(result.verificationStatus).toBe('pass');
      expect(result.adaptorValid).toBe(true);
      expect(result.refundSigValid).toBe(true);
      expect(result.signAdaptorValid).toBe(true);
      expect(result.signRefundSigValid).toBe(true);
      expect(result.signContractIdMatches).toBe(true);
      expect(result.refundTxId).toBeTruthy();
      expect(result.fundOutputIndex).not.toBeNull();
      expect(result.cets).toHaveLength(result.outcomes.length);
    });

    it('keeps cryptographic verification independent from policy expectations', async () => {
      const result = await verifyDlc(signedSample.offer, signedSample.accept, {
        signHex: signedSample.sign,
        network: 'regtest',
      });

      expect(result.verificationStatus).toBe('pass');
      expect(result.expectedOraclePubkey).toBeNull();
      expect(result.verificationIncomplete).toEqual([]);
    });

    it('fails when the accepter refund signature is changed', async () => {
      const result = await verifyDlc(
        signedSample.offer,
        corruptAcceptRefundSignature(signedSample.accept),
        {
          signHex: signedSample.sign,
          expectedOraclePubkey: signedSample.oraclePubkey,
          network: 'regtest',
        },
      );

      expect(result.refundSigValid).toBe(false);
      expect(result.verificationStatus).toBe('fail');
    });

    it('fails when an offerer adaptor signature is changed', async () => {
      const result = await verifyDlc(signedSample.offer, signedSample.accept, {
        signHex: corruptSignAdaptorSignatures(signedSample.sign),
        expectedOraclePubkey: signedSample.oraclePubkey,
        network: 'regtest',
      });

      expect(result.signAdaptorValid).toBe(false);
      expect(result.verificationStatus).toBe('fail');
    });

    it('fails when the offerer refund signature is changed', async () => {
      const result = await verifyDlc(signedSample.offer, signedSample.accept, {
        signHex: corruptSignRefundSignature(signedSample.sign),
        expectedOraclePubkey: signedSample.oraclePubkey,
        network: 'regtest',
      });

      expect(result.signRefundSigValid).toBe(false);
      expect(result.verificationStatus).toBe('fail');
    });

    it('evaluates lender terms and returns a deterministic attestation payload', async () => {
      const baseline = await verifyDlc(signedSample.offer, signedSample.accept, {
        signHex: signedSample.sign,
        expectedOraclePubkey: signedSample.oraclePubkey,
        network: 'regtest',
      });
      const result = await verifyDlcAgainstPolicy(signedSample.offer, signedSample.accept, signedSample.sign, {
        lenderRole: 'offerer',
        network: 'regtest',
        expectedOraclePubkey: signedSample.oraclePubkey,
        expectedLenderFundingPubkey: baseline.offererFundingPubkey!,
        expectedLenderPayoutAddress: baseline.offererPayoutAddress!,
        expectedTotalCollateralSats: baseline.totalCollateral!,
        oracleEvent: { expectedEventId: baseline.oracleEventId! },
        expectedCetLocktime: baseline.cetLocktime!,
        expectedRefundLocktime: baseline.refundLocktime!,
        expectedLenderOutcomes: [{ outcome: 'repaid', lenderPayoutSats: '8000' }],
      });

      expect(result.verdict).toBe('pass');
      expect(result.cryptographicVerification).toBe('pass');
      expect(result.policyVerification).toBe('pass');
      expect(result.policyCoverage).toBe('complete');
      expect(result.checks.every((check) => check.status === 'pass')).toBe(true);
      expect(result.verificationDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(result.attestationPayload.cetTxids).toHaveLength(baseline.cets.length);
    });

    it('supports cryptographic verification without any policy', async () => {
      const result = await verifyDlcAgainstPolicy(signedSample.offer, signedSample.accept, signedSample.sign);

      expect(result.verdict).toBe('incomplete');
      expect(result.cryptographicVerification).toBe('pass');
      expect(result.policyVerification).toBe('not_provided');
      expect(result.policyCoverage).toBe('not_provided');
      expect(result.checks).toEqual([]);
      expect(result.attestationPayload.policyHash).toBeNull();
    });

    it('supports an oracle-pubkey-only partial policy', async () => {
      const result = await verifyDlcAgainstPolicy(
        signedSample.offer,
        signedSample.accept,
        signedSample.sign,
        {
          expectedOraclePubkey: signedSample.oraclePubkey,
        },
        'regtest',
      );

      expect(result.verdict).toBe('incomplete');
      expect(result.cryptographicVerification).toBe('pass');
      expect(result.policyVerification).toBe('pass');
      expect(result.policyCoverage).toBe('partial');
      expect(result.verification.network).toBe('regtest');
      expect(result.checks.some((check) => check.id === 'network')).toBe(false);
      expect(result.checks).toEqual([
        expect.objectContaining({ id: 'oracle-pubkey', status: 'pass' }),
      ]);
    });

    it('can evaluate a partial policy without DlcSign while marking crypto incomplete', async () => {
      const result = await verifyDlcAgainstPolicy(signedSample.offer, signedSample.accept, undefined, {
        expectedOraclePubkey: signedSample.oraclePubkey,
      });

      expect(result.verdict).toBe('incomplete');
      expect(result.cryptographicVerification).toBe('incomplete');
      expect(result.policyVerification).toBe('pass');
      expect(result.policyCoverage).toBe('partial');
    });

    it('fails only the supplied partial policy when the oracle pubkey mismatches', async () => {
      const result = await verifyDlcAgainstPolicy(signedSample.offer, signedSample.accept, signedSample.sign, {
        expectedOraclePubkey: generateRandomXOnlyPubkey(),
      });

      expect(result.verdict).toBe('fail');
      expect(result.cryptographicVerification).toBe('pass');
      expect(result.policyVerification).toBe('fail');
      expect(result.policyCoverage).toBe('partial');
      expect(result.checks).toEqual([
        expect.objectContaining({ id: 'oracle-pubkey', status: 'fail' }),
      ]);
    });

    it('checks policy network against the resolved address network, not the offer chain hash', async () => {
      const result = await verifyDlcAgainstPolicy(
        signedSample.offer,
        signedSample.accept,
        signedSample.sign,
        { network: 'mainnet' },
        'mainnet',
      );

      expect(result.verification.network).toBe('mainnet');
      expect(result.verification.chainHashNetwork).toBe('regtest');
      expect(result.policyVerification).toBe('pass');
      expect(result.checks).toEqual([expect.objectContaining({ id: 'network', status: 'pass' })]);
    });

    it('returns a policy failure for a malformed oracle event instead of throwing', async () => {
      const malformedPolicy = { oracleEvent: {} } as unknown as DlcVerificationPolicy;
      const result = await verifyDlcAgainstPolicy(
        signedSample.offer,
        signedSample.accept,
        signedSample.sign,
        malformedPolicy,
        'regtest',
      );

      expect(result.cryptographicVerification).toBe('pass');
      expect(result.policyVerification).toBe('fail');
      expect(result.verdict).toBe('fail');
      expect(result.checks).toEqual([expect.objectContaining({ id: 'oracle-event-id', status: 'fail' })]);
    });
  });

  describe('Loan oracle event ID policy', () => {
    it('matches the canonical loan event ID derivation', () => {
      expect(
        deriveLygosOracleEventId({
          eventType: ' loan-matured ',
          loanId: ' loan-123 ',
          repaymentAddress: ' bc1qrepayment ',
          repaymentAmount: ' 100000 ',
        }),
      ).toBe('loan-matured-3a0c8f7e56452482f216ca063904ee5f58c7cfe2e245982599955fcae2668071');
    });

    it('binds the repayment address into the derived event ID', () => {
      const base = {
        eventType: 'loan-matured',
        loanId: 'loan-123',
        repaymentAddress: 'bc1qrepayment',
        repaymentAmount: '100000',
      };
      expect(deriveLygosOracleEventId(base)).not.toBe(
        deriveLygosOracleEventId({ ...base, repaymentAddress: 'bc1qdifferent' }),
      );
    });
  });
});
