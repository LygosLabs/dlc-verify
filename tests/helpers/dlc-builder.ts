/**
 * DLC Message Builder Helpers
 *
 * Utility functions for constructing and modifying DLC messages programmatically.
 * Used for testing verification logic by creating valid messages and introducing
 * controlled modifications to test failure detection.
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { DlcOffer, DlcAccept } = require('@node-dlc/messaging');

export interface DlcOfferMessage {
  contractInfo: {
    totalCollateral: bigint;
    contractDescriptor?: {
      outcomes: Array<{ outcome: string; localPayout: bigint }>;
    };
    oracleInfo?: {
      announcement?: {
        oraclePublicKey: Buffer;
        oracleEvent: {
          oracleNonces: Buffer[];
          eventId?: string;
        };
      };
    };
  };
  offerCollateral: bigint;
  fundingPubkey: Buffer;
  payoutSpk: Buffer;
  payoutSerialId: bigint;
  changeSpk: Buffer;
  changeSerialId: bigint;
  cetLocktime: number;
  refundLocktime: number;
  feeRatePerVb: bigint;
  fundOutputSerialId: bigint;
  fundingInputs: Array<{
    prevTx: {
      txId: { toString: () => string };
      outputs: Array<{ value?: { sats?: bigint } }>;
    };
    prevTxVout: number;
    maxWitnessLen: number;
    inputSerialId: bigint;
  }>;
  chainHash: Buffer;
  temporaryContractId: Buffer;
  serialize: () => Buffer;
}

export interface DlcAcceptMessage {
  acceptCollateral: bigint;
  fundingPubkey: Buffer;
  payoutSpk: Buffer;
  payoutSerialId: bigint;
  changeSpk: Buffer;
  changeSerialId: bigint;
  fundingInputs: Array<{
    prevTx: {
      txId: { toString: () => string };
      outputs: Array<{ value?: { sats?: bigint } }>;
    };
    prevTxVout: number;
    maxWitnessLen: number;
    inputSerialId: bigint;
  }>;
  cetAdaptorSignatures?: {
    sigs?: Array<{ encryptedSig: Buffer; dleqProof: Buffer }>;
  };
  serialize: () => Buffer;
}

/**
 * Deserialize a DLC offer from hex
 */
export function deserializeOffer(hex: string): DlcOfferMessage {
  return DlcOffer.deserialize(Buffer.from(hex, 'hex'));
}

/**
 * Deserialize a DLC accept from hex
 */
export function deserializeAccept(hex: string): DlcAcceptMessage {
  return DlcAccept.deserialize(Buffer.from(hex, 'hex'));
}

/**
 * Serialize a DLC offer to hex
 */
export function serializeOffer(offer: DlcOfferMessage): string {
  return offer.serialize().toString('hex');
}

/**
 * Serialize a DLC accept to hex
 */
export function serializeAccept(accept: DlcAcceptMessage): string {
  return accept.serialize().toString('hex');
}

/**
 * Load sample DLC data from the examples directory
 */
export function loadSampleData(): { offer: string; accept: string } {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require('fs');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const path = require('path');

  const samplePath = path.resolve(__dirname, '../../examples/sample.json');
  const raw = fs.readFileSync(samplePath, 'utf-8');
  return JSON.parse(raw);
}

/**
 * Clone an offer by serializing and deserializing
 * This creates a deep copy that can be safely modified
 */
export function cloneOffer(offer: DlcOfferMessage): DlcOfferMessage {
  const hex = serializeOffer(offer);
  return deserializeOffer(hex);
}

/**
 * Clone an accept by serializing and deserializing
 * This creates a deep copy that can be safely modified
 */
export function cloneAccept(accept: DlcAcceptMessage): DlcAcceptMessage {
  const hex = serializeAccept(accept);
  return deserializeAccept(hex);
}

/**
 * Modify the CET locktime in an offer
 * Returns a new serialized offer hex with the modified locktime
 */
export function modifyCetLocktime(offerHex: string, newLocktime: number): string {
  const offer = deserializeOffer(offerHex);
  offer.cetLocktime = newLocktime;
  return serializeOffer(offer);
}

/**
 * Modify the refund locktime in an offer
 * Returns a new serialized offer hex with the modified locktime
 */
export function modifyRefundLocktime(offerHex: string, newLocktime: number): string {
  const offer = deserializeOffer(offerHex);
  offer.refundLocktime = newLocktime;
  return serializeOffer(offer);
}

/**
 * Modify the offer collateral amount
 * Returns a new serialized offer hex with the modified collateral
 */
export function modifyOfferCollateral(offerHex: string, newCollateral: bigint): string {
  const offer = deserializeOffer(offerHex);
  offer.offerCollateral = newCollateral;
  return serializeOffer(offer);
}

/**
 * Modify the accept collateral amount
 * Returns a new serialized accept hex with the modified collateral
 */
export function modifyAcceptCollateral(acceptHex: string, newCollateral: bigint): string {
  const accept = deserializeAccept(acceptHex);
  accept.acceptCollateral = newCollateral;
  return serializeAccept(accept);
}

/**
 * Modify the funding pubkey in an offer
 * Returns a new serialized offer hex with the modified pubkey
 */
export function modifyOfferFundingPubkey(offerHex: string, newPubkey: Buffer): string {
  const offer = deserializeOffer(offerHex);
  offer.fundingPubkey = newPubkey;
  return serializeOffer(offer);
}

/**
 * Modify the funding pubkey in an accept
 * Returns a new serialized accept hex with the modified pubkey
 */
export function modifyAcceptFundingPubkey(acceptHex: string, newPubkey: Buffer): string {
  const accept = deserializeAccept(acceptHex);
  accept.fundingPubkey = newPubkey;
  return serializeAccept(accept);
}

/**
 * Corrupt adaptor signatures by flipping bytes
 * Returns a new serialized accept hex with corrupted signatures
 */
export function corruptAdaptorSignatures(acceptHex: string): string {
  const accept = deserializeAccept(acceptHex);

  if (accept.cetAdaptorSignatures?.sigs?.length) {
    // Flip some bytes in the first adaptor signature
    const firstSig = accept.cetAdaptorSignatures.sigs[0];
    if (firstSig.encryptedSig.length > 10) {
      // Flip byte at position 10
      firstSig.encryptedSig[10] ^= 0xff;
    }
  }

  return serializeAccept(accept);
}

/**
 * Get the oracle pubkey from an offer
 */
export function getOraclePubkey(offerHex: string): string | null {
  const offer = deserializeOffer(offerHex);
  const oracleInfo = offer.contractInfo?.oracleInfo;
  const announcement = oracleInfo?.announcement;
  return announcement?.oraclePublicKey?.toString('hex') || null;
}

/**
 * Generate a random 33-byte compressed pubkey (for testing wrong pubkeys)
 */
export function generateRandomPubkey(): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const crypto = require('crypto');
  // Generate a random 32-byte value and prefix with 02 or 03 for compressed pubkey
  const randomBytes = crypto.randomBytes(32);
  const prefix = randomBytes[0] % 2 === 0 ? 0x02 : 0x03;
  return Buffer.concat([Buffer.from([prefix]), randomBytes]);
}

/**
 * Generate a random 32-byte x-only pubkey (for testing wrong oracle pubkeys)
 */
export function generateRandomXOnlyPubkey(): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const crypto = require('crypto');
  return crypto.randomBytes(32).toString('hex');
}
