import { describe, it, expect, beforeAll } from 'vitest';
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

    it('should successfully verify CET adaptor signatures (Tier 2)', async () => {
      const result = await verifyDlc(sampleOffer, sampleAccept);

      expect(result.tier2Available).toBe(true);
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

      // Adaptor signatures should either fail (false) or tier2 not be available (null)
      // because modifying collateral changes the CET outputs
      expect(result.adaptorValid !== true).toBe(true);
    });

    it('should fail adaptor verification when offerer funding pubkey is modified', async () => {
      const randomPubkey = generateRandomPubkey();
      const modifiedOfferHex = modifyOfferFundingPubkey(sampleOffer, randomPubkey);
      const result = await verifyDlc(modifiedOfferHex, sampleAccept);

      // The funding pubkey should reflect the modified value
      expect(result.offererFundingPubkey).toBe(randomPubkey.toString('hex'));

      // Adaptor signatures should either fail (false) or tier2 not be available (null)
      // because the funding script changed
      expect(result.adaptorValid !== true).toBe(true);
    });

    it('should fail adaptor verification when accepter funding pubkey is modified', async () => {
      const randomPubkey = generateRandomPubkey();
      const modifiedAcceptHex = modifyAcceptFundingPubkey(sampleAccept, randomPubkey);
      const result = await verifyDlc(sampleOffer, modifiedAcceptHex);

      // The funding pubkey should reflect the modified value
      expect(result.accepterFundingPubkey).toBe(randomPubkey.toString('hex'));

      // Adaptor signatures should either fail (false) or tier2 not be available (null)
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
});
