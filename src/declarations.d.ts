declare module 'bip-schnorr' {
  export function verify(pubkey: Buffer, message: Buffer, signature: Buffer): boolean;
  export const math: {
    taggedHash(tag: string, data: Buffer): Buffer;
  };
}

declare module 'bitcoin-networks' {
  import type { Network } from 'bitcoinjs-lib';

  export const BitcoinNetworks: {
    bitcoin: Network;
    bitcoin_testnet: Network;
    bitcoin_regtest: Network;
    [key: string]: Network;
  };

  export function chainHashFromNetwork(network: Network): Buffer;
}

declare module '@node-dlc/core' {
  export class DlcTxBuilder {
    constructor(offer: unknown, accept: unknown);
    buildFundingTransaction(): { toHex(): string };
  }
}

declare module '@node-dlc/messaging' {
  export class DlcOffer {
    static deserialize(data: Buffer): DlcOffer;
    chainHash: Buffer;
    fundingPubkey: Buffer;
    changeSpk: Buffer;
    payoutSpk: Buffer;
    offerCollateral: bigint;
    cetLocktime: number;
    refundLocktime: number;
    feeRatePerVb: bigint;
    temporaryContractId: Buffer;
    fundOutputSerialId: bigint;
    changeSerialId: bigint;
    payoutSerialId: bigint;
    fundingInputs: Array<{
      prevTx: {
        txId: { toString(): string };
        outputs: Array<{ value?: { sats?: bigint } }>;
      };
      prevTxVout: number;
      sequence: { value: number };
      scriptSigLength(): number;
      maxWitnessLen: number;
      inputSerialId: bigint;
      dlcInput?: { contractId?: Buffer };
    }>;
    contractInfo: {
      contractDescriptor?: unknown;
      oracleInfo?: unknown;
      totalCollateral: bigint;
      contractOraclePairs?: Array<{ contractDescriptor?: unknown; oracleInfo?: unknown }>;
    };
  }

  export class DlcAccept {
    static deserialize(data: Buffer): DlcAccept;
    fundingPubkey: Buffer;
    changeSpk: Buffer;
    payoutSpk: Buffer;
    acceptCollateral: bigint;
    changeSerialId: bigint;
    payoutSerialId: bigint;
    fundingInputs: Array<{
      prevTx: {
        txId: { toString(): string };
        outputs: Array<{ value?: { sats?: bigint } }>;
      };
      prevTxVout: number;
      maxWitnessLen: number;
      inputSerialId: bigint;
      dlcInput?: { contractId?: Buffer };
    }>;
    cetAdaptorSignatures?:
      | {
          sigs?: Array<{ encryptedSig: Buffer; dleqProof: Buffer }>;
        }
      | Array<{ encryptedSig: Buffer; dleqProof: Buffer }>;
  }

  export class EnumeratedDescriptor {
    outcomes: Array<{ outcome: string; localPayout: bigint }>;
  }

  export class NumericalDescriptor {
    numDigits: number;
  }

  export class SingleOracleInfo {
    announcement: OracleAnnouncement;
  }

  export class MultiOracleInfo {
    announcements: OracleAnnouncement[];
  }

  interface OracleAnnouncement {
    oraclePublicKey: Buffer;
    oracleEvent: {
      serialize(): Buffer;
      eventId?: string;
      eventMaturityEpoch?: number;
      oracleNonces: Buffer[];
    };
    announcementSig: Buffer;
    getEventId?(): string;
    getEventMaturityEpoch?(): number;
  }
}
