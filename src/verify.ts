import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { verify, math } = require('bip-schnorr');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { BitcoinNetworks, chainHashFromNetwork } = require('bitcoin-networks');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { DlcTxBuilder } = require('@node-dlc/core');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const {
  DlcOffer,
  DlcAccept,
  EnumeratedDescriptor,
  NumericalDescriptor,
  SingleOracleInfo,
  MultiOracleInfo,
} = require('@node-dlc/messaging');

import type {
  VerificationResult,
  Tier2Result,
  VerifyOptions,
  CliArgs,
  SampleData,
  FundingAddressInfo,
  ContractInfo,
  SingleFundedComputation,
  DdkModule,
  PartyParams,
  DlcTransactions,
  OutcomeInfo,
  FundingInput,
} from './types';

const LOCKTIME_THRESHOLD = 500000000;

const HELP_TEXT = `
DLC Verify - Cryptographic DLC verification tool

Usage:
  node dist/verify.js [options]

Options:
  --offer <hex>           DLC offer message hex
  --accept <hex>          DLC accept message hex
  --oracle-pubkey <hex>   Expected oracle x-only pubkey (optional)
  --help, -h              Show this help

Examples:
  node dist/verify.js                              # Use sample data
  node dist/verify.js --offer <hex> --accept <hex> # Verify custom DLC
  node dist/verify.js --offer <hex> --accept <hex> --oracle-pubkey <hex>

The tool performs two tiers of verification:
  Tier 1: Structural verification (collateral, outcomes, oracle info)
  Tier 2: Cryptographic verification (CET adaptor signatures via DDK)
`.trim();

function loadSampleData(): SampleData {
  const samplePath = path.resolve(__dirname, '../examples/sample.json');
  if (!fs.existsSync(samplePath)) {
    throw new Error(`Sample data not found at ${samplePath}`);
  }
  const raw = fs.readFileSync(samplePath, 'utf-8');
  return JSON.parse(raw) as SampleData;
}

function normalizeOraclePubkeyHex(pubkey: string | undefined | null): string | null {
  if (pubkey === undefined || pubkey === null) return null;
  const normalized = String(pubkey).trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
  if (!normalized) return null;
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error('Oracle pubkey must be hex');
  }
  if (normalized.length !== 64) {
    throw new Error('Oracle pubkey must be a 32-byte x-only pubkey (64 hex chars)');
  }
  return normalized;
}

function parseCliArgs(args: string[]): CliArgs {
  const sample = loadSampleData();
  const parsed: CliArgs = {
    offerHex: sample.offer,
    acceptHex: sample.accept,
    expectedOraclePubkey: null,
    showHelp: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.showHelp = true;
      continue;
    }
    if (arg === '--offer' && args[i + 1]) {
      parsed.offerHex = args[++i];
      continue;
    }
    if (arg === '--accept' && args[i + 1]) {
      parsed.acceptHex = args[++i];
      continue;
    }
    if (arg === '--oracle-pubkey' && args[i + 1]) {
      parsed.expectedOraclePubkey = args[++i];
      continue;
    }
  }

  return parsed;
}

/**
 * Verify a DLC offer/accept pair and return structured JSON result.
 * @param offerHex - hex-encoded DlcOffer message
 * @param acceptHex - hex-encoded DlcAccept message
 * @param options - verification options
 * @returns structured verification result
 */
export async function verifyDlc(
  offerHex: string,
  acceptHex: string,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const result: VerificationResult = {
    // Tier 1
    contractType: null,
    totalCollateral: null,
    offerCollateral: null,
    acceptCollateral: null,
    outcomes: [],
    oraclePubkey: null,
    extractedOraclePubkey: null,
    expectedOraclePubkey: null,
    oraclePubkeySource: 'derived',
    oraclePubkeyMatchesExpected: null,
    oracleEventId: null,
    oracleSigValid: false,
    oracleSigError: null,
    cetLocktime: null,
    refundLocktime: null,
    feeRatePerVb: null,
    offererFundingPubkey: null,
    accepterFundingPubkey: null,
    fundingAddress: null,
    witnessScript: null,
    offerInputs: [],
    acceptInputs: [],
    contractId: null,
    // Tier 2
    tier2Available: false,
    tier2Note: null,
    fundTxId: null,
    cetCount: null,
    adaptorValid: null,
    adaptorValidCount: 0,
    adaptorTotalCount: 0,
    adaptorError: null,
    // errors
    error: null,
  };

  try {
    const expectedOraclePubkey = normalizeOraclePubkeyHex(options.expectedOraclePubkey);
    const offer = DlcOffer.deserialize(Buffer.from(offerHex, 'hex'));
    const accept = DlcAccept.deserialize(Buffer.from(acceptHex, 'hex'));

    const contract = extractContractInfo(offer.contractInfo);
    const descriptor = contract.descriptor;
    const oracleAnnouncement = extractOracleAnnouncement(contract.oracleInfo);

    const totalCollateral = contract.totalCollateral;
    const offerCollateral = offer.offerCollateral;
    const acceptCollateral = accept.acceptCollateral;

    const network = detectNetwork(offer.chainHash);
    const fundingAddress = reconstructFundingAddress(offer.fundingPubkey, accept.fundingPubkey, network);

    // Populate basic fields
    result.totalCollateral = totalCollateral.toString();
    result.offerCollateral = offerCollateral.toString();
    result.acceptCollateral = acceptCollateral.toString();
    result.cetLocktime = offer.cetLocktime;
    result.refundLocktime = offer.refundLocktime;
    result.feeRatePerVb = offer.feeRatePerVb.toString();
    result.offererFundingPubkey = offer.fundingPubkey.toString('hex');
    result.accepterFundingPubkey = accept.fundingPubkey.toString('hex');
    result.fundingAddress = fundingAddress.address || null;
    result.witnessScript = fundingAddress.witnessScriptHex;

    // Contract type and outcomes
    if (descriptor instanceof EnumeratedDescriptor) {
      result.contractType = 'Enumerated';
      result.outcomes = descriptor.outcomes.map((o: { outcome: string; localPayout: bigint }): OutcomeInfo => ({
        label: o.outcome,
        offererSats: o.localPayout.toString(),
        accepterSats: (totalCollateral - o.localPayout).toString(),
      }));
    } else if (descriptor instanceof NumericalDescriptor) {
      result.contractType = `Numerical (${descriptor.numDigits} digits)`;
    } else {
      result.contractType = 'unknown';
    }

    // Funding inputs
    result.offerInputs = buildFundingInputsReport(offer.fundingInputs).map(
      (i: { outpoint: string; sats?: bigint }): FundingInput => ({
        outpoint: i.outpoint,
        sats: i.sats !== undefined ? i.sats.toString() : null,
      }),
    );
    result.acceptInputs = buildFundingInputsReport(accept.fundingInputs).map(
      (i: { outpoint: string; sats?: bigint }): FundingInput => ({
        outpoint: i.outpoint,
        sats: i.sats !== undefined ? i.sats.toString() : null,
      }),
    );

    // Oracle info
    const extractedOraclePubkey = oracleAnnouncement?.oraclePublicKey?.toString('hex') || null;
    result.extractedOraclePubkey = extractedOraclePubkey;
    result.expectedOraclePubkey = expectedOraclePubkey;
    result.oraclePubkey = expectedOraclePubkey || extractedOraclePubkey;
    result.oraclePubkeySource = expectedOraclePubkey ? 'provided' : 'derived';
    result.oraclePubkeyMatchesExpected = expectedOraclePubkey
      ? expectedOraclePubkey === extractedOraclePubkey
      : null;
    result.oracleEventId = oracleAnnouncement?.getEventId?.() || oracleAnnouncement?.oracleEvent?.eventId || null;

    // Oracle signature verification
    if (oracleAnnouncement) {
      try {
        const msg = math.taggedHash('DLC/oracle/announcement/v0', oracleAnnouncement.oracleEvent.serialize());
        verify(oracleAnnouncement.oraclePublicKey, msg, oracleAnnouncement.announcementSig);
        result.oracleSigValid = true;
        result.oracleSigError = null;
      } catch (e) {
        result.oracleSigValid = false;
        result.oracleSigError = (e as Error).message;
      }
    }

    // Compute contract ID
    const singleFundedComputation = tryComputeContractIdFromSingleFunded(offer, accept, fundingAddress);
    if (singleFundedComputation) {
      result.contractId = singleFundedComputation.cidRpcTxid;
    } else {
      const embeddedIds = [
        ...offer.fundingInputs.map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex')).filter(Boolean),
        ...accept.fundingInputs.map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex')).filter(Boolean),
      ];
      if (embeddedIds.length > 0) {
        result.contractId = embeddedIds[0] as string;
      }
    }

    // Tier 2 verification
    const tier2 = await tryTier2(offer, accept, descriptor, fundingAddress, oracleAnnouncement);
    result.tier2Available = tier2.available;
    result.tier2Note = tier2.note || null;
    result.fundTxId = tier2.fundTxId;
    result.cetCount = tier2.cetCount;
    result.adaptorValid = tier2.adaptorValid;
    result.adaptorValidCount = tier2.adaptorValidCount;
    result.adaptorTotalCount = tier2.adaptorTotalCount;
    result.adaptorError = tier2.adaptorError;
  } catch (err) {
    result.error = (err as Error).message;
  }

  return result;
}

function satsToBtc(sats: bigint | number | string): string {
  return (Number(sats) / 1e8).toFixed(8);
}

function amountFmt(sats: bigint | number | string): string {
  return `${satsToBtc(sats)} BTC (${sats} sats)`;
}

function locktimeToHuman(locktime: number): string {
  if (locktime >= LOCKTIME_THRESHOLD) {
    return `${new Date(locktime * 1000).toISOString()} UTC`;
  }
  return `block height ${locktime}`;
}

function detectNetwork(chainHash: Buffer): bitcoin.Network {
  const entries = Object.values(BitcoinNetworks);
  for (const net of entries) {
    const netTyped = net as bitcoin.Network;
    if (chainHash.equals(chainHashFromNetwork(netTyped))) {
      return netTyped;
    }
  }
  return BitcoinNetworks.bitcoin_regtest;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractContractInfo(contractInfo: any): ContractInfo {
  if (contractInfo.contractDescriptor) {
    return {
      descriptor: contractInfo.contractDescriptor,
      oracleInfo: contractInfo.oracleInfo,
      totalCollateral: contractInfo.totalCollateral as bigint,
      kind: 'single',
    };
  }

  const firstPair = contractInfo.contractOraclePairs?.[0];
  return {
    descriptor: firstPair?.contractDescriptor,
    oracleInfo: firstPair?.oracleInfo,
    totalCollateral: contractInfo.totalCollateral as bigint,
    kind: 'disjoint',
  };
}

interface OracleAnnouncementResult {
  oraclePublicKey: Buffer;
  oracleEvent: { serialize: () => Buffer; eventId?: string; eventMaturityEpoch?: number; oracleNonces: Buffer[] };
  announcementSig: Buffer;
  getEventId?: () => string;
  getEventMaturityEpoch?: () => number;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractOracleAnnouncement(oracleInfo: any): OracleAnnouncementResult | null {
  if (oracleInfo instanceof SingleOracleInfo) return oracleInfo.announcement;
  if (oracleInfo instanceof MultiOracleInfo) return oracleInfo.announcements?.[0];
  if (oracleInfo?.announcement) return oracleInfo.announcement;
  if (oracleInfo?.announcements?.length) return oracleInfo.announcements[0];
  return null;
}

interface FundingInputReport {
  outpoint: string;
  sats?: bigint;
}

function buildFundingInputsReport(inputs: Array<{
  prevTx: { txId: { toString: () => string }; outputs: Array<{ value?: { sats?: bigint } }> };
  prevTxVout: number;
}>): FundingInputReport[] {
  return inputs.map((input) => {
    const txid = input.prevTx.txId.toString();
    const vout = input.prevTxVout;
    const out = input.prevTx.outputs[vout];
    const sats = out?.value?.sats;
    return {
      outpoint: `${txid}:${vout}`,
      sats,
    };
  });
}

function buildPartyParamsInputs(inputs: Array<{
  prevTx: { txId: { toString: () => string } };
  prevTxVout: number;
  maxWitnessLen: number;
  inputSerialId: bigint;
}>): Array<{ txid: string; vout: number; scriptSig: Buffer; maxWitnessLength: number; serialId: bigint }> {
  return inputs.map((input) => ({
    txid: input.prevTx.txId.toString(),
    vout: input.prevTxVout,
    scriptSig: Buffer.alloc(0),
    maxWitnessLength: input.maxWitnessLen,
    serialId: BigInt(input.inputSerialId),
  }));
}

function sumFundingInputAmount(inputs: Array<{
  prevTx: { outputs: Array<{ value?: { sats?: bigint } }> };
  prevTxVout: number;
}>): bigint {
  return inputs.reduce((sum, input) => {
    const prevOutput = input.prevTx.outputs[input.prevTxVout];
    return sum + BigInt(prevOutput?.value?.sats ?? 0n);
  }, 0n);
}

function reconstructFundingAddress(
  offerFundingPubkey: Buffer,
  acceptFundingPubkey: Buffer,
  network: bitcoin.Network,
): FundingAddressInfo {
  const pubkeys = [offerFundingPubkey, acceptFundingPubkey].sort(Buffer.compare);
  const p2ms = bitcoin.payments.p2ms({ m: 2, pubkeys, network });
  const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms, network });

  return {
    address: p2wsh.address,
    witnessScriptHex: p2ms.output ? Buffer.from(p2ms.output).toString('hex') : 'n/a',
    scriptPubKeyHex: p2wsh.output ? Buffer.from(p2wsh.output).toString('hex') : null,
  };
}

function getFundingScriptAndScriptPubKey(
  offerFundingPubkey: Buffer,
  acceptFundingPubkey: Buffer,
): { fundingScript: Buffer | undefined; fundingScriptPubKey: Buffer | undefined } {
  const pubkeys =
    Buffer.compare(offerFundingPubkey, acceptFundingPubkey) < 0
      ? [offerFundingPubkey, acceptFundingPubkey]
      : [acceptFundingPubkey, offerFundingPubkey];
  const p2ms = bitcoin.payments.p2ms({ m: 2, pubkeys });
  const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms });

  return {
    fundingScript: p2ms.output ? Buffer.from(p2ms.output) : undefined,
    fundingScriptPubKey: p2wsh.output ? Buffer.from(p2wsh.output) : undefined,
  };
}

function findFundOutput(
  outputs: Array<{ scriptPubkey?: Buffer; script?: Buffer; value: bigint }>,
  fundingScriptPubKey: Buffer | undefined,
): { value: bigint } | null {
  if (!fundingScriptPubKey) return null;
  const targetScriptHex = Buffer.from(fundingScriptPubKey).toString('hex');
  for (const output of outputs) {
    const outputScriptHex = Buffer.from(output.scriptPubkey ?? output.script ?? []).toString('hex');
    if (outputScriptHex === targetScriptHex) return output;
  }
  return null;
}

function computeContractIdFromFundingOutpoint(
  tempContractId: Buffer,
  fundTxIdHex: string,
  fundOutputIndex: number,
): string {
  const fundingTxId = Buffer.from(fundTxIdHex, 'hex');
  if (fundingTxId.length !== 32 || tempContractId.length !== 32) {
    throw new Error('Expected 32-byte fundingTxId and temporaryContractId');
  }

  const mixed = Buffer.from(fundingTxId);
  mixed[30] ^= (fundOutputIndex >> 8) & 0xff;
  mixed[31] ^= fundOutputIndex & 0xff;

  const contractId = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    contractId[i] = mixed[i] ^ tempContractId[i];
  }

  return contractId.toString('hex');
}

function estimateSingleFundedFee(
  offer: {
    fundingInputs: Array<{ scriptSigLength: () => number; maxWitnessLen: number }>;
    changeSpk: Buffer;
    fundOutputSerialId: bigint;
    changeSerialId: bigint;
    feeRatePerVb: bigint;
  },
  inCount: number,
  _outCount: number,
  hasWitness: boolean,
): bigint {
  const varIntSize = (n: number): number => (n < 0xfd ? 1 : 3);
  const inputBaseSize = offer.fundingInputs.reduce(
    (sum, input) => sum + 32 + 4 + varIntSize(input.scriptSigLength()) + input.scriptSigLength() + 4,
    0,
  );
  const outputScripts = [
    { serialId: offer.fundOutputSerialId, scriptHex: null as string | null },
    { serialId: offer.changeSerialId, scriptHex: offer.changeSpk.toString('hex') },
  ];
  const outputBaseSize = outputScripts.reduce((sum, out) => {
    const scriptLen = out.scriptHex ? out.scriptHex.length / 2 : 34;
    return sum + 8 + varIntSize(scriptLen) + scriptLen;
  }, 0);

  const strippedSize =
    4 + // version
    varIntSize(inCount) +
    inputBaseSize +
    varIntSize(2) +
    outputBaseSize +
    4; // locktime

  const witnessSize =
    (hasWitness ? 2 : 0) + offer.fundingInputs.reduce((sum, input) => sum + input.maxWitnessLen, 0);

  const vbytes = Math.ceil((strippedSize * 4 + witnessSize) / 4);
  return BigInt(vbytes) * offer.feeRatePerVb;
}

function tryComputeContractIdFromSingleFunded(
  offer: {
    fundingInputs: Array<{
      prevTx: { txId: { toString: () => string }; outputs: Array<{ value?: { sats?: bigint } }> };
      prevTxVout: number;
      sequence: { value: number };
      scriptSigLength: () => number;
      maxWitnessLen: number;
    }>;
    offerCollateral: bigint;
    temporaryContractId: Buffer;
    changeSpk: Buffer;
    fundOutputSerialId: bigint;
    changeSerialId: bigint;
    feeRatePerVb: bigint;
    contractInfo: { totalCollateral: bigint };
  },
  accept: {
    acceptCollateral: bigint;
    fundingInputs: Array<unknown>;
    fundingPubkey: Buffer;
  },
  fundingAddress: FundingAddressInfo,
  feeOverride?: bigint,
): SingleFundedComputation | null {
  if (accept.acceptCollateral !== 0n || accept.fundingInputs.length > 0) {
    return null;
  }

  const offerInputTotal = offer.fundingInputs.reduce((sum, input) => {
    const out = input.prevTx.outputs[input.prevTxVout];
    return sum + (out?.value?.sats ?? 0n);
  }, 0n);

  if (!fundingAddress.scriptPubKeyHex) return null;

  // Prefer exact reconstruction from node-dlc's transaction builder.
  if (feeOverride === undefined) {
    try {
      const builtFundTx = new DlcTxBuilder(offer, accept).buildFundingTransaction();
      const builtFundTxHex = builtFundTx.toHex();
      const parsedFundTx = bitcoin.Transaction.fromHex(builtFundTxHex);
      const fundTxId = parsedFundTx.getId();
      const fundOutputIndex = parsedFundTx.outs.findIndex(
        (out) => Buffer.from(out.script).toString('hex') === fundingAddress.scriptPubKeyHex,
      );
      if (fundOutputIndex >= 0) {
        const totalOutput = parsedFundTx.outs.reduce((sum, out) => sum + BigInt(out.value), 0n);
        const fee = offerInputTotal - totalOutput;
        const offerChange = parsedFundTx.outs.reduce((sum, out) => {
          const scriptHex = Buffer.from(out.script).toString('hex');
          if (scriptHex === offer.changeSpk.toString('hex')) return sum + BigInt(out.value);
          return sum;
        }, 0n);

        const cidRpcTxid = computeContractIdFromFundingOutpoint(
          offer.temporaryContractId,
          fundTxId,
          fundOutputIndex,
        );
        const cidInternalTxid = computeContractIdFromFundingOutpoint(
          offer.temporaryContractId,
          Buffer.from(fundTxId, 'hex').reverse().toString('hex'),
          fundOutputIndex,
        );

        return {
          fundTxId,
          fundOutputIndex,
          fee,
          offerChange,
          cidRpcTxid,
          cidInternalTxid,
        };
      }
    } catch {
      // Fallback to model-based reconstruction below.
    }
  }

  const inCount = offer.fundingInputs.length;
  const outCount = 2;
  const fee = feeOverride ?? estimateSingleFundedFee(offer, inCount, outCount, true);
  const offerChange = offerInputTotal - offer.offerCollateral - fee;
  if (offerChange < 0n) return null;

  const tx = new bitcoin.Transaction();
  tx.version = 2;
  tx.locktime = 0;

  for (const input of offer.fundingInputs) {
    const txidLE = Buffer.from(input.prevTx.txId.toString(), 'hex').reverse();
    tx.addInput(txidLE, input.prevTxVout, input.sequence.value, Buffer.alloc(0));
  }

  const outputs = [
    {
      serialId: offer.fundOutputSerialId,
      value: offer.contractInfo.totalCollateral,
      scriptHex: fundingAddress.scriptPubKeyHex,
      kind: 'fund' as const,
    },
    {
      serialId: offer.changeSerialId,
      value: offerChange,
      scriptHex: offer.changeSpk.toString('hex'),
      kind: 'change' as const,
    },
  ].sort((a, b) => (a.serialId < b.serialId ? -1 : 1));

  for (const output of outputs) {
    tx.addOutput(Buffer.from(output.scriptHex, 'hex'), BigInt(output.value));
  }

  const fundTxId = tx.getId();
  const fundOutputIndex = outputs.findIndex((o) => o.kind === 'fund');
  if (fundOutputIndex < 0) return null;

  const cidRpcTxid = computeContractIdFromFundingOutpoint(
    offer.temporaryContractId,
    fundTxId,
    fundOutputIndex,
  );
  const cidInternalTxid = computeContractIdFromFundingOutpoint(
    offer.temporaryContractId,
    Buffer.from(fundTxId, 'hex').reverse().toString('hex'),
    fundOutputIndex,
  );

  return {
    fundTxId,
    fundOutputIndex,
    fee,
    offerChange,
    cidRpcTxid,
    cidInternalTxid,
  };
}

async function initCfd(): Promise<DdkModule> {
  // Tier 2 uses DDK (ddk-ts native binary) for adaptor sig verification.
  // Probe for ddk-ts native binary (arm64 or x64)
  const ddkPaths = [
    path.join(__dirname, '../node_modules/@bennyblader/ddk-ts/dist/ddk-ts.darwin-arm64.node'),
    path.join(__dirname, '../node_modules/@bennyblader/ddk-ts/dist/ddk-ts.darwin-x64.node'),
    path.join(__dirname, '../node_modules/@bennyblader/ddk-ts/dist/ddk-ts.linux-x64-gnu.node'),
  ];

  for (const ddkPath of ddkPaths) {
    if (!fs.existsSync(ddkPath)) continue;
    const m = { exports: {} as DdkModule };
    process.dlopen(m, ddkPath);
    return m.exports;
  }

  throw new Error('Could not find ddk-ts native binary for Tier 2 verification');
}

function getTaggedOutcomeHash(outcomeText: string): Buffer {
  const tag = Buffer.from('DLC/oracle/attestation/v0', 'utf8');
  const tagHash = crypto.createHash('sha256').update(tag).digest();
  const outcomeBytes = Buffer.from(outcomeText, 'utf8');
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([tagHash, tagHash, outcomeBytes]))
    .digest();
}

async function tryTier2(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  offer: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  accept: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  descriptor: any,
  _fundingAddress: FundingAddressInfo,
  oracleAnnouncement: OracleAnnouncementResult | null,
): Promise<Tier2Result> {
  const result: Tier2Result = {
    available: false,
    note: '',
    fundTxId: null,
    cetCount: null,
    adaptorValid: null,
    adaptorValidCount: 0,
    adaptorTotalCount: 0,
    adaptorError: null,
    refundSigValid: null,
    computedContractId: null,
  };

  try {
    const ddk = await initCfd();
    if (!(descriptor instanceof EnumeratedDescriptor)) {
      throw new Error('Tier 2 currently supports EnumeratedDescriptor contracts only');
    }

    if (!oracleAnnouncement?.oraclePublicKey || !oracleAnnouncement?.oracleEvent?.oracleNonces?.length) {
      throw new Error('Missing oracle announcement pubkey/nonce for adaptor verification');
    }

    const offerTyped = offer as {
      fundingPubkey: Buffer;
      changeSpk: Buffer;
      changeSerialId: bigint;
      payoutSpk: Buffer;
      payoutSerialId: bigint;
      fundingInputs: Array<{
        prevTx: { txId: { toString: () => string }; outputs: Array<{ value?: { sats?: bigint } }> };
        prevTxVout: number;
        maxWitnessLen: number;
        inputSerialId: bigint;
      }>;
      offerCollateral: bigint;
      refundLocktime: number;
      feeRatePerVb: bigint;
      cetLocktime: number;
      fundOutputSerialId: bigint;
      contractInfo: { totalCollateral: bigint };
    };

    const acceptTyped = accept as {
      fundingPubkey: Buffer;
      changeSpk: Buffer;
      changeSerialId: bigint;
      payoutSpk: Buffer;
      payoutSerialId: bigint;
      fundingInputs: Array<{
        prevTx: { txId: { toString: () => string }; outputs: Array<{ value?: { sats?: bigint } }> };
        prevTxVout: number;
        maxWitnessLen: number;
        inputSerialId: bigint;
      }>;
      acceptCollateral: bigint;
      cetAdaptorSignatures?: { sigs?: Array<{ encryptedSig: Buffer; dleqProof: Buffer }> } | Array<{ encryptedSig: Buffer; dleqProof: Buffer }>;
    };

    // Build DLC transactions via DDK (deterministic reconstruction)
    const outcomes = descriptor.outcomes.map((o: { outcome: string; localPayout: bigint }) => ({
      offer: BigInt(o.localPayout),
      accept: BigInt(offerTyped.contractInfo.totalCollateral) - BigInt(o.localPayout),
    }));

    const localParams: PartyParams = {
      fundPubkey: offerTyped.fundingPubkey,
      changeScriptPubkey: offerTyped.changeSpk,
      changeSerialId: BigInt(offerTyped.changeSerialId),
      payoutScriptPubkey: offerTyped.payoutSpk,
      payoutSerialId: BigInt(offerTyped.payoutSerialId),
      inputs: buildPartyParamsInputs(offerTyped.fundingInputs),
      inputAmount: sumFundingInputAmount(offerTyped.fundingInputs),
      collateral: BigInt(offerTyped.offerCollateral),
      dlcInputs: [],
    };

    const remoteParams: PartyParams = {
      fundPubkey: acceptTyped.fundingPubkey,
      changeScriptPubkey: acceptTyped.changeSpk,
      changeSerialId: BigInt(acceptTyped.changeSerialId),
      payoutScriptPubkey: acceptTyped.payoutSpk,
      payoutSerialId: BigInt(acceptTyped.payoutSerialId),
      inputs: buildPartyParamsInputs(acceptTyped.fundingInputs),
      inputAmount: sumFundingInputAmount(acceptTyped.fundingInputs),
      collateral: BigInt(acceptTyped.acceptCollateral),
      dlcInputs: [],
    };

    const dlcTxs = ddk.createDlcTransactions(
      outcomes,
      localParams,
      remoteParams,
      offerTyped.refundLocktime,
      BigInt(offerTyped.feeRatePerVb),
      0,
      offerTyped.cetLocktime,
      BigInt(offerTyped.fundOutputSerialId),
    );

    // Compute fund txid from DDK-built fund transaction
    const fundTxId = crypto
      .createHash('sha256')
      .update(crypto.createHash('sha256').update(dlcTxs.fund.rawBytes).digest())
      .digest()
      .reverse()
      .toString('hex');

    // Build tagged attestation messages: Array<Array<Array<Buffer>>> (per-CET → per-oracle → msgs)
    const messagesForDdk = descriptor.outcomes.map((o: { outcome: string }) => [[getTaggedOutcomeHash(o.outcome)]]);

    const { fundingScript, fundingScriptPubKey } = getFundingScriptAndScriptPubKey(
      offerTyped.fundingPubkey,
      acceptTyped.fundingPubkey,
    );

    const oracleInfo = [
      {
        publicKey: oracleAnnouncement.oraclePublicKey,
        nonces: oracleAnnouncement.oracleEvent.oracleNonces,
      },
    ];

    // Adaptor pairs: for enum contracts, concat encryptedSig + dleqProof into signature field
    const adaptorSigsRaw = acceptTyped.cetAdaptorSignatures;
    const adaptorSigs = Array.isArray(adaptorSigsRaw)
      ? adaptorSigsRaw
      : (adaptorSigsRaw?.sigs || []);
    const adaptorPairs = adaptorSigs.map((sig: { encryptedSig: Buffer; dleqProof: Buffer }) => ({
      signature: Buffer.concat([sig.encryptedSig, sig.dleqProof]),
      proof: Buffer.from(''),
    }));

    const fundOutput = findFundOutput(dlcTxs.fund.outputs, fundingScriptPubKey);
    if (!fundOutput) {
      throw new Error('Could not locate fund output in reconstructed funding transaction');
    }

    const isValid = ddk.verifyCetAdaptorSigsFromOracleInfo(
      adaptorPairs,
      dlcTxs.cets,
      oracleInfo,
      acceptTyped.fundingPubkey,
      fundingScript!,
      fundOutput.value,
      messagesForDdk,
    );

    result.available = true;
    result.fundTxId = fundTxId;
    result.cetCount = dlcTxs.cets.length;
    result.adaptorTotalCount = adaptorSigs.length;
    result.adaptorValidCount = isValid ? adaptorSigs.length : 0;
    result.adaptorValid = isValid;
    result.adaptorError = isValid ? null : 'DDK verifyCetAdaptorSigsFromOracleInfo returned false';
    result.note = isValid
      ? `All ${result.adaptorTotalCount} CET adaptor signatures cryptographically valid (DDK)`
      : 'Adaptor signature verification failed';
    return result;
  } catch (err) {
    result.note = `Tier 2 unavailable: ${(err as Error).message}`;
    return result;
  }
}

async function main(): Promise<void> {
  const { offerHex, acceptHex, expectedOraclePubkey, showHelp } = parseCliArgs(process.argv.slice(2));

  if (showHelp) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  const normalizedExpectedOraclePubkey = normalizeOraclePubkeyHex(expectedOraclePubkey);
  const offer = DlcOffer.deserialize(Buffer.from(offerHex, 'hex'));
  const accept = DlcAccept.deserialize(Buffer.from(acceptHex, 'hex'));

  const contract = extractContractInfo(offer.contractInfo);
  const descriptor = contract.descriptor;
  const oracleAnnouncement = extractOracleAnnouncement(contract.oracleInfo);

  const totalCollateral = contract.totalCollateral;
  const offerCollateral = offer.offerCollateral;
  const acceptCollateral = accept.acceptCollateral;

  const network = detectNetwork(offer.chainHash);
  const fundingAddress = reconstructFundingAddress(offer.fundingPubkey, accept.fundingPubkey, network);

  let contractType = 'unknown';
  let outcomes: Array<{ label: string; offererSats: bigint; accepterSats: bigint }> = [];

  if (descriptor instanceof EnumeratedDescriptor) {
    contractType = 'Enumerated';
    outcomes = descriptor.outcomes.map((o: { outcome: string; localPayout: bigint }) => ({
      label: o.outcome,
      offererSats: o.localPayout,
      accepterSats: totalCollateral - o.localPayout,
    }));
  } else if (descriptor instanceof NumericalDescriptor) {
    contractType = `Numerical (${descriptor.numDigits} digits)`;
  }

  const offerInputs = buildFundingInputsReport(offer.fundingInputs);
  const acceptInputs = buildFundingInputsReport(accept.fundingInputs);

  const extractedOraclePubkey = oracleAnnouncement?.oraclePublicKey?.toString('hex') || 'n/a';
  const oraclePubkey = normalizedExpectedOraclePubkey || extractedOraclePubkey;
  const oraclePubkeySource = normalizedExpectedOraclePubkey ? 'provided' : 'derived';
  const oraclePubkeyMatchesExpected = normalizedExpectedOraclePubkey
    ? normalizedExpectedOraclePubkey === extractedOraclePubkey
    : null;
  const oracleEventId = oracleAnnouncement?.getEventId?.() || oracleAnnouncement?.oracleEvent?.eventId || 'n/a';
  const eventMaturityEpoch = oracleAnnouncement?.getEventMaturityEpoch?.() || oracleAnnouncement?.oracleEvent?.eventMaturityEpoch;

  let oracleSigValid = false;
  let oracleSigError = 'n/a';
  if (oracleAnnouncement) {
    try {
      const msg = math.taggedHash('DLC/oracle/announcement/v0', oracleAnnouncement.oracleEvent.serialize());
      verify(oracleAnnouncement.oraclePublicKey, msg, oracleAnnouncement.announcementSig);
      oracleSigValid = true;
      oracleSigError = '';
    } catch (e) {
      oracleSigError = (e as Error).message;
    }
  }

  const tier2 = await tryTier2(offer, accept, descriptor, fundingAddress, oracleAnnouncement);
  const singleFundedComputation = tryComputeContractIdFromSingleFunded(
    offer as Parameters<typeof tryComputeContractIdFromSingleFunded>[0],
    accept as Parameters<typeof tryComputeContractIdFromSingleFunded>[1],
    fundingAddress,
  );

  let computedContractId = 'n/a';
  if (tier2.computedContractId) {
    computedContractId = tier2.computedContractId;
  } else if (singleFundedComputation) {
    computedContractId = `${singleFundedComputation.cidRpcTxid} (rpc-txid convention)`;
  } else {
    const embeddedIds = [
      ...offer.fundingInputs.map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex')).filter(Boolean),
      ...accept.fundingInputs.map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex')).filter(Boolean),
    ];
    if (embeddedIds.length > 0) {
      const unique = [...new Set(embeddedIds)];
      computedContractId =
        unique.length === 1
          ? `${unique[0]} (from embedded DlcInput)`
          : `${unique.join(', ')} (embedded DlcInput values differ)`;
    }
  }

  const lines: string[] = [];
  lines.push('DLC Verification Report');
  lines.push('=======================');
  lines.push('');
  lines.push(`Contract type: ${contractType}`);
  lines.push(`Total collateral: ${amountFmt(totalCollateral)}`);
  lines.push(`Offer collateral: ${amountFmt(offerCollateral)}`);
  lines.push(`Accept collateral: ${amountFmt(acceptCollateral)}`);
  lines.push('');
  lines.push('Outcomes and payouts:');
  if (outcomes.length === 0) {
    lines.push('  - n/a (non-enumerated contract)');
  } else {
    for (const row of outcomes) {
      lines.push(`  - ${row.label}: offerer ${row.offererSats} sats / accepter ${row.accepterSats} sats`);
    }
  }
  lines.push('');
  lines.push(`Oracle pubkey: ${oraclePubkey}`);
  lines.push(`Oracle pubkey source: ${oraclePubkeySource}`);
  if (normalizedExpectedOraclePubkey) {
    lines.push(`Oracle pubkey extracted from DLC: ${extractedOraclePubkey}`);
    lines.push(
      `Oracle pubkey match: ${oraclePubkeyMatchesExpected ? 'matches provided oracle pubkey' : 'DOES NOT MATCH provided oracle pubkey'}`,
    );
  }
  lines.push(`Oracle event ID: ${oracleEventId}`);
  lines.push(`Oracle announcement Schnorr signature: ${oracleSigValid ? 'valid' : `invalid (${oracleSigError})`}`);
  lines.push(
    `Loan maturity date: ${locktimeToHuman(offer.cetLocktime)}${eventMaturityEpoch ? ` (oracle event maturity: ${locktimeToHuman(eventMaturityEpoch)})` : ''}`,
  );
  lines.push(`Refund locktime: ${locktimeToHuman(offer.refundLocktime)}`);
  lines.push(`Fee rate: ${offer.feeRatePerVb.toString()} sat/vB`);
  lines.push('');
  lines.push(`Offerer funding pubkey: ${offer.fundingPubkey.toString('hex')}`);
  lines.push(`Accepter funding pubkey: ${accept.fundingPubkey.toString('hex')}`);
  lines.push(`2-of-2 P2WSH address: ${fundingAddress.address || 'n/a'}`);
  lines.push(`2-of-2 witness script: ${fundingAddress.witnessScriptHex}`);
  lines.push('');
  lines.push('Offerer funding inputs:');
  for (const input of offerInputs) {
    lines.push(`  - ${input.outpoint}, amount: ${input.sats !== undefined ? amountFmt(input.sats) : 'unknown'}`);
  }
  lines.push('');
  lines.push('Accepter funding inputs:');
  for (const input of acceptInputs) {
    lines.push(`  - ${input.outpoint}, amount: ${input.sats !== undefined ? amountFmt(input.sats) : 'unknown'}`);
  }
  lines.push('');
  lines.push(`Contract ID (computed): ${computedContractId}`);
  if (singleFundedComputation) {
    lines.push(`Contract ID (computed, internal-txid convention): ${singleFundedComputation.cidInternalTxid}`);
    lines.push(`Reconstructed fund TX ID (single-funded model): ${singleFundedComputation.fundTxId}`);
    lines.push(`Reconstructed fund output index: ${singleFundedComputation.fundOutputIndex}`);
    lines.push(`Estimated fund tx fee: ${singleFundedComputation.fee} sats`);
  }

  lines.push('');
  lines.push('Tier 2 status:');
  if (tier2.available) {
    if (tier2.fundTxId) lines.push(`  Fund TX ID: ${tier2.fundTxId}`);
    if (tier2.cetCount !== null) lines.push(`  CET count: ${tier2.cetCount}`);
    if (tier2.adaptorValid === true) {
      lines.push(
        `  CET adaptor signatures: CRYPTOGRAPHICALLY VALID (${tier2.adaptorValidCount}/${tier2.adaptorTotalCount})`,
      );
    }
    if (tier2.adaptorValid === false) {
      lines.push(
        `  CET adaptor signatures: CRYPTOGRAPHICALLY INVALID (${tier2.adaptorValidCount}/${tier2.adaptorTotalCount})${tier2.adaptorError ? ` - ${tier2.adaptorError}` : ''}`,
      );
    }
    if (tier2.refundSigValid === true) lines.push('  Refund signature: CRYPTOGRAPHICALLY VALID');
    if (tier2.refundSigValid === false) lines.push('  Refund signature: CRYPTOGRAPHICALLY INVALID');
    if (tier2.note) lines.push(`  Note: ${tier2.note}`);
  } else {
    lines.push(`  ${tier2.note}`);
    lines.push(`  Adaptor signatures: CRYPTOGRAPHICALLY INVALID (${tier2.note})`);
  }

  if (!tier2.available || !tier2.fundTxId) {
    lines.push('  Contract ID from funding outpoint formula requires reconstructed fund tx + output index.');
  }

  console.log(lines.join('\n'));
}

// CLI entry point
if (require.main === module) {
  main().catch((err) => {
    console.error((err as Error).message);
    process.exit(1);
  });
}
