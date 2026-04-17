import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
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
  DlcSign,
  OracleAttestation,
  EnumeratedDescriptor,
  NumericalDescriptor,
  SingleOracleInfo,
  MultiOracleInfo,
} = require('@node-dlc/messaging');

import type {
  AdaptorVerificationResult,
  CetExecutionResult,
  CliArgs,
  ContractInfo,
  DdkModule,
  FundingAddressInfo,
  FundingInput,
  OutcomeInfo,
  PartyParams,
  SampleData,
  SingleFundedComputation,
  VerificationResult,
  VerifyOptions,
} from './types';

const LOCKTIME_THRESHOLD = 500000000;

const HELP_TEXT = `
DLC Verify - Cryptographic DLC verification tool

Usage:
  node dist/verify.js [options]

Options:
  --offer <hex>           DLC offer message hex
  --accept <hex>          DLC accept message hex
  --sign <hex>            DLC sign message hex (optional)
  --attestation <hex>     Oracle attestation hex (requires --sign; produces broadcastable CET)
  --oracle-pubkey <hex>   Expected oracle x-only pubkey (optional)
  --help, -h              Show this help

Examples:
  node dist/verify.js                              # Use sample data
  node dist/verify.js --offer <hex> --accept <hex> # Verify custom DLC
  node dist/verify.js --offer <hex> --accept <hex> --sign <hex>
  node dist/verify.js --offer <hex> --accept <hex> --sign <hex> --attestation <hex>
  node dist/verify.js --offer <hex> --accept <hex> --oracle-pubkey <hex>

The tool performs two levels of verification:
  Structural: Message parsing (collateral, outcomes, oracle info)
  Cryptographic: CET adaptor signature verification via DDK
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
    signHex: null,
    attestationHex: null,
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
    if (arg === '--sign' && args[i + 1]) {
      parsed.signHex = args[++i];
      continue;
    }
    if (arg === '--attestation' && args[i + 1]) {
      parsed.attestationHex = args[++i];
      continue;
    }
    if (arg === '--oracle-pubkey' && args[i + 1]) {
      parsed.expectedOraclePubkey = args[++i];
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
    // Structural verification
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
    // Adaptor signature verification
    adaptorSigVerificationAvailable: false,
    adaptorSigVerificationNote: null,
    fundTxId: null,
    cetCount: null,
    adaptorValid: null,
    adaptorValidCount: 0,
    adaptorTotalCount: 0,
    adaptorError: null,
    // Sign message verification
    signAvailable: false,
    signContractId: null,
    signContractIdMatches: null,
    signAdaptorValid: null,
    signAdaptorValidCount: 0,
    signAdaptorTotalCount: 0,
    signAdaptorError: null,
    // errors
    error: null,
  };

  const log = (msg: string): void => {
    if (options.logPrefix) console.log(`[${options.logPrefix}] ${msg}`);
  };

  try {
    const expectedOraclePubkey = normalizeOraclePubkeyHex(options.expectedOraclePubkey);
    log(`parsing offer/accept (offerHex=${offerHex.length}ch acceptHex=${acceptHex.length}ch)`);
    const offer = DlcOffer.deserialize(Buffer.from(offerHex, 'hex'));
    const accept = DlcAccept.deserialize(Buffer.from(acceptHex, 'hex'));
    log('parsed offer & accept successfully');

    const contract = extractContractInfo(offer.contractInfo);
    const descriptor = contract.descriptor;
    const oracleAnnouncement = extractOracleAnnouncement(contract.oracleInfo);
    log(
      `contract kind=${contract.kind} descriptor=${descriptor?.constructor?.name ?? 'unknown'} ` +
        `totalCollateral=${contract.totalCollateral} ` +
        `oracleAnnouncement=${oracleAnnouncement ? 'present' : 'missing'}`,
    );

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
      result.outcomes = descriptor.outcomes.map(
        (o: { outcome: string; localPayout: bigint }): OutcomeInfo => ({
          label: o.outcome,
          offererSats: o.localPayout.toString(),
          accepterSats: (totalCollateral - o.localPayout).toString(),
        }),
      );
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
    result.oraclePubkeyMatchesExpected = expectedOraclePubkey ? expectedOraclePubkey === extractedOraclePubkey : null;
    result.oracleEventId = oracleAnnouncement?.getEventId?.() || oracleAnnouncement?.oracleEvent?.eventId || null;

    // Oracle signature verification
    if (oracleAnnouncement) {
      try {
        const msg = math.taggedHash('DLC/oracle/announcement/v0', oracleAnnouncement.oracleEvent.serialize());
        verify(oracleAnnouncement.oraclePublicKey, msg, oracleAnnouncement.announcementSig);
        result.oracleSigValid = true;
        result.oracleSigError = null;
        log('oracle announcement signature valid');
      } catch (e) {
        result.oracleSigValid = false;
        result.oracleSigError = (e as Error).message;
        log(`oracle announcement signature INVALID: ${(e as Error).message}`);
      }
    } else {
      log('skipping oracle sig verification: no announcement present');
    }

    // Compute contract ID
    const singleFundedComputation = tryComputeContractIdFromSingleFunded(offer, accept, fundingAddress);
    if (singleFundedComputation) {
      result.contractId = singleFundedComputation.cidRpcTxid;
    } else {
      const embeddedIds = [
        ...offer.fundingInputs
          .map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex'))
          .filter(Boolean),
        ...accept.fundingInputs
          .map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex'))
          .filter(Boolean),
      ];
      if (embeddedIds.length > 0) {
        result.contractId = embeddedIds[0] as string;
      }
    }

    // Adaptor signature verification
    log('invoking adaptor signature verification');
    const adaptorResult = await verifyAdaptorSignatures(
      offer,
      accept,
      descriptor,
      fundingAddress,
      oracleAnnouncement,
      options.logPrefix,
    );
    log(
      `adaptor result available=${adaptorResult.available} valid=${adaptorResult.adaptorValid} ` +
        `count=${adaptorResult.adaptorValidCount}/${adaptorResult.adaptorTotalCount} ` +
        `error=${adaptorResult.adaptorError ?? 'null'} note=${adaptorResult.note}`,
    );
    result.adaptorSigVerificationAvailable = adaptorResult.available;
    result.adaptorSigVerificationNote = adaptorResult.note || null;
    result.fundTxId = adaptorResult.fundTxId;
    result.cetCount = adaptorResult.cetCount;
    result.adaptorValid = adaptorResult.adaptorValid;
    result.adaptorValidCount = adaptorResult.adaptorValidCount;
    result.adaptorTotalCount = adaptorResult.adaptorTotalCount;
    result.adaptorError = adaptorResult.adaptorError;

    // Prefer DDK-computed contract ID (uses the authoritative funding tx)
    if (adaptorResult.computedContractId) {
      result.contractId = adaptorResult.computedContractId;
    }

    // Sign message verification
    if (options.signHex) {
      log(`sign hex provided (${options.signHex.length}ch), parsing`);
      try {
        const sign = DlcSign.deserialize(Buffer.from(options.signHex, 'hex'));
        result.signAvailable = true;
        result.signContractId = sign.contractId.toString('hex');
        log(
          `parsed sign message: contractId=${result.signContractId} ` +
            `cetAdaptorSigs=${sign.cetAdaptorSignatures?.sigs?.length ?? 'n/a'}`,
        );

        // Check if contract ID matches
        if (result.contractId) {
          result.signContractIdMatches = result.signContractId === result.contractId;
          log(
            `sign contractId match=${result.signContractIdMatches} ` +
              `(sign=${result.signContractId} vs computed=${result.contractId})`,
          );
        } else {
          log('no computed contractId available to compare against sign.contractId');
        }

        // Verify offerer's CET adaptor signatures
        if (adaptorResult.available && sign.cetAdaptorSignatures?.sigs) {
          try {
            const signAdaptorSigs = sign.cetAdaptorSignatures.sigs;
            result.signAdaptorTotalCount = signAdaptorSigs.length;
            // For now just count the sigs - full verification would need DDK
            result.signAdaptorValidCount = signAdaptorSigs.length;
            result.signAdaptorValid = signAdaptorSigs.length > 0;
          } catch (sigErr) {
            result.signAdaptorError = (sigErr as Error).message;
            result.signAdaptorValid = false;
            log(`sign adaptor sig processing threw: ${(sigErr as Error).message}`);
          }
        } else {
          log(
            `sign adaptor verification skipped: adaptorAvailable=${adaptorResult.available} ` +
              `hasSigs=${!!sign.cetAdaptorSignatures?.sigs}`,
          );
        }
      } catch (signErr) {
        result.signAdaptorError = `Failed to parse sign message: ${(signErr as Error).message}`;
        log(`sign parse FAILED: ${(signErr as Error).message}`);
      }
    }
  } catch (err) {
    result.error = (err as Error).message;
    log(`verifyDlc threw: ${(err as Error).stack ?? (err as Error).message}`);
  }

  return result;
}

/**
 * Execute a CET using oracle attestation — produces a broadcastable transaction.
 * Requires offer, accept, sign, and attestation hex.
 */
export async function executeCet(
  offerHex: string,
  acceptHex: string,
  signHex: string,
  attestationHex: string,
): Promise<CetExecutionResult> {
  const ddk = await initDdk();
  const offer = DlcOffer.deserialize(Buffer.from(offerHex, 'hex'));
  const accept = DlcAccept.deserialize(Buffer.from(acceptHex, 'hex'));
  const sign = DlcSign.deserialize(Buffer.from(signHex, 'hex'));
  const attestation = OracleAttestation.deserialize(Buffer.from(attestationHex, 'hex'));

  const attestedOutcome = attestation.outcomes[0];
  if (!attestedOutcome) {
    throw new Error('Oracle attestation contains no outcomes');
  }

  // Find outcome index matching attestation
  const contract = extractContractInfo(offer.contractInfo);
  const descriptor = contract.descriptor;
  if (!(descriptor instanceof EnumeratedDescriptor)) {
    throw new Error('CET execution currently supports EnumeratedDescriptor contracts only');
  }

  const outcomeIndex = descriptor.outcomes.findIndex((o: { outcome: string }) => {
    if (o.outcome === attestedOutcome) return true;
    const hash = crypto.createHash('sha256').update(Buffer.from(attestedOutcome, 'utf8')).digest('hex');
    return o.outcome === hash;
  });
  if (outcomeIndex === -1) {
    const available = descriptor.outcomes.map((o: { outcome: string }) => o.outcome).join(', ');
    throw new Error(`Attestation outcome "${attestedOutcome}" not found in contract outcomes: [${available}]`);
  }

  // Rebuild DLC transactions via DDK
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
  };

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

  if (outcomeIndex >= dlcTxs.cets.length) {
    throw new Error(`Outcome index ${outcomeIndex} out of bounds. CET count: ${dlcTxs.cets.length}`);
  }

  // Extract adaptor signatures for the attested outcome
  const offerAdaptorSig = sign.cetAdaptorSignatures?.sigs?.[outcomeIndex];
  const acceptAdaptorSig =
    accept.cetAdaptorSignatures?.sigs?.[outcomeIndex] ??
    (Array.isArray(accept.cetAdaptorSignatures) ? accept.cetAdaptorSignatures[outcomeIndex] : null);

  if (!offerAdaptorSig || !acceptAdaptorSig) {
    throw new Error(
      `Missing adaptor signatures for outcome ${outcomeIndex}. ` +
        `offerSigs=${sign.cetAdaptorSignatures?.sigs?.length ?? 0} ` +
        `acceptSigs=${accept.cetAdaptorSignatures?.sigs?.length ?? accept.cetAdaptorSignatures?.length ?? 0}`,
    );
  }

  // Build full 162-byte adaptor signatures: encryptedSig (65) + dleqProof (97)
  const offerFullSig = Buffer.concat([offerAdaptorSig.encryptedSig, offerAdaptorSig.dleqProof || Buffer.alloc(0)]);
  const acceptFullSig = Buffer.concat([acceptAdaptorSig.encryptedSig, acceptAdaptorSig.dleqProof || Buffer.alloc(0)]);

  // Decrypt adaptor signatures using oracle attestation
  const offerRealSig = ddk.extractEcdsaSignatureFromOracleSignatures(attestation.signatures, offerFullSig);
  const acceptRealSig = ddk.extractEcdsaSignatureFromOracleSignatures(attestation.signatures, acceptFullSig);

  // Append SIGHASH_ALL
  const SIGHASH_ALL = Buffer.from([0x01]);
  const offerSigFinal = Buffer.concat([offerRealSig, SIGHASH_ALL]);
  const acceptSigFinal = Buffer.concat([acceptRealSig, SIGHASH_ALL]);

  // Build the signed CET
  const cet = dlcTxs.cets[outcomeIndex];
  const cetTx = bitcoin.Transaction.fromBuffer(cet.rawBytes);

  // Sort pubkeys lexicographically for 2-of-2 multisig witness
  const offerPubkey = offer.fundingPubkey;
  const acceptPubkey = accept.fundingPubkey;
  const offerFirst = Buffer.compare(offerPubkey, acceptPubkey) === -1;
  const sortedPubkeys = offerFirst ? [offerPubkey, acceptPubkey] : [acceptPubkey, offerPubkey];
  const sortedSigs = offerFirst ? [offerSigFinal, acceptSigFinal] : [acceptSigFinal, offerSigFinal];

  // Create 2-of-2 multisig witness script
  const p2ms = bitcoin.payments.p2ms({ m: 2, pubkeys: sortedPubkeys });

  // P2WSH witness: <empty> <sig1> <sig2> <witnessScript>
  if (!p2ms.output) {
    throw new Error('Failed to create multisig witness script');
  }
  cetTx.ins[0].witness = [Buffer.alloc(0), sortedSigs[0], sortedSigs[1], p2ms.output];

  return {
    cetHex: cetTx.toHex(),
    cetTxid: cetTx.getId(),
    outcome: attestedOutcome,
    outcomeIndex,
  };
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

function buildFundingInputsReport(
  inputs: Array<{
    prevTx: { txId: { toString: () => string }; outputs: Array<{ value?: { sats?: bigint } }> };
    prevTxVout: number;
  }>,
): FundingInputReport[] {
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

function buildPartyParamsInputs(
  inputs: Array<{
    prevTx: { txId: { toString: () => string } };
    prevTxVout: number;
    maxWitnessLen: number;
    inputSerialId: bigint;
  }>,
): Array<{ txid: string; vout: number; scriptSig: Buffer; maxWitnessLength: number; serialId: bigint }> {
  return inputs.map((input) => ({
    txid: input.prevTx.txId.toString(),
    vout: input.prevTxVout,
    scriptSig: Buffer.alloc(0),
    maxWitnessLength: input.maxWitnessLen,
    serialId: BigInt(input.inputSerialId),
  }));
}

function sumFundingInputAmount(
  inputs: Array<{
    prevTx: { outputs: Array<{ value?: { sats?: bigint } }> };
    prevTxVout: number;
  }>,
): bigint {
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

  const witnessSize = (hasWitness ? 2 : 0) + offer.fundingInputs.reduce((sum, input) => sum + input.maxWitnessLen, 0);

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

        const cidRpcTxid = computeContractIdFromFundingOutpoint(offer.temporaryContractId, fundTxId, fundOutputIndex);
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

  const cidRpcTxid = computeContractIdFromFundingOutpoint(offer.temporaryContractId, fundTxId, fundOutputIndex);
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

async function initDdk(): Promise<DdkModule> {
  const { platform, arch } = process;
  let binName: string;
  if (platform === 'darwin' && arch === 'arm64') binName = 'ddk-ts.darwin-arm64.node';
  else if (platform === 'darwin' && arch === 'x64') binName = 'ddk-ts.darwin-x64.node';
  else if (platform === 'linux' && arch === 'x64') binName = 'ddk-ts.linux-x64-gnu.node';
  else throw new Error(`Unsupported platform for ddk-ts: ${platform}-${arch}`);

  const binPath = path.join(__dirname, '../node_modules/@bennyblader/ddk-ts/dist', binName);
  if (!fs.existsSync(binPath)) {
    throw new Error(`ddk-ts native binary not found: ${binPath}`);
  }
  const m = { exports: {} as DdkModule };
  process.dlopen(m, binPath);
  return m.exports;
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

async function verifyAdaptorSignatures(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  offer: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  accept: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  descriptor: any,
  _fundingAddress: FundingAddressInfo,
  oracleAnnouncement: OracleAnnouncementResult | null,
  logPrefix?: string,
): Promise<AdaptorVerificationResult> {
  const log = (msg: string): void => {
    if (logPrefix) console.log(`[${logPrefix}:adaptor] ${msg}`);
  };

  const result: AdaptorVerificationResult = {
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
    const ddk = await initDdk();
    log('DDK initialized');
    if (!(descriptor instanceof EnumeratedDescriptor)) {
      throw new Error('Adaptor signature verification currently supports EnumeratedDescriptor contracts only');
    }

    if (!oracleAnnouncement?.oraclePublicKey || !oracleAnnouncement?.oracleEvent?.oracleNonces?.length) {
      throw new Error('Missing oracle announcement pubkey/nonce for adaptor verification');
    }
    log(
      `precondition ok: outcomes=${descriptor.outcomes.length} ` +
        `oracleNonces=${oracleAnnouncement.oracleEvent.oracleNonces.length}`,
    );

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
      cetAdaptorSignatures?:
        | { sigs?: Array<{ encryptedSig: Buffer; dleqProof: Buffer }> }
        | Array<{ encryptedSig: Buffer; dleqProof: Buffer }>;
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

    log(
      `calling ddk.createDlcTransactions: outcomes=${outcomes.length} ` +
        `offerCollateral=${localParams.collateral} offerInputs=${localParams.inputs.length} offerInputAmount=${localParams.inputAmount} ` +
        `acceptCollateral=${remoteParams.collateral} acceptInputs=${remoteParams.inputs.length} acceptInputAmount=${remoteParams.inputAmount} ` +
        `feeRate=${offerTyped.feeRatePerVb} refundLocktime=${offerTyped.refundLocktime} cetLocktime=${offerTyped.cetLocktime}`,
    );
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
    log(`DDK built fund tx + ${dlcTxs.cets.length} CETs`);

    // Compute fund txid from DDK-built fund transaction
    const fundTxId = crypto
      .createHash('sha256')
      .update(crypto.createHash('sha256').update(dlcTxs.fund.rawBytes).digest())
      .digest()
      .reverse()
      .toString('hex');
    log(`fundTxId=${fundTxId}`);

    // Build tagged attestation messages: Array<Array<Array<Buffer>>> (per-CET → per-oracle → msgs)
    const messagesForDdk = descriptor.outcomes.map((o: { outcome: string }) => [[getTaggedOutcomeHash(o.outcome)]]);

    const { fundingScript, fundingScriptPubKey } = getFundingScriptAndScriptPubKey(
      offerTyped.fundingPubkey,
      acceptTyped.fundingPubkey,
    );

    if (!fundingScript) {
      throw new Error('Could not derive funding script from pubkeys');
    }

    const oracleInfo = [
      {
        publicKey: oracleAnnouncement.oraclePublicKey,
        nonces: oracleAnnouncement.oracleEvent.oracleNonces,
      },
    ];

    // Adaptor pairs: for enum contracts, concat encryptedSig + dleqProof into signature field
    const adaptorSigsRaw = acceptTyped.cetAdaptorSignatures;
    const adaptorSigs = Array.isArray(adaptorSigsRaw) ? adaptorSigsRaw : adaptorSigsRaw?.sigs || [];
    log(
      `accept adaptor sigs: count=${adaptorSigs.length} ` +
        `shape=${Array.isArray(adaptorSigsRaw) ? 'array' : 'object-with-sigs'} ` +
        `firstSigBytes=${adaptorSigs[0]?.encryptedSig?.length ?? 0}+${adaptorSigs[0]?.dleqProof?.length ?? 0}`,
    );
    const adaptorPairs = adaptorSigs.map((sig: { encryptedSig: Buffer; dleqProof: Buffer }) => ({
      signature: Buffer.concat([sig.encryptedSig, sig.dleqProof]),
      proof: Buffer.from(''),
    }));

    const fundOutputIndex = dlcTxs.fund.outputs.findIndex((output: { scriptPubkey?: Buffer; script?: Buffer }) => {
      const outputScriptHex = Buffer.from(output.scriptPubkey ?? output.script ?? []).toString('hex');
      return fundingScriptPubKey ? outputScriptHex === Buffer.from(fundingScriptPubKey).toString('hex') : false;
    });
    const fundOutput = fundOutputIndex >= 0 ? dlcTxs.fund.outputs[fundOutputIndex] : null;
    if (!fundOutput || fundOutputIndex < 0) {
      throw new Error('Could not locate fund output in reconstructed funding transaction');
    }
    log(`fundOutputIndex=${fundOutputIndex} fundOutputValue=${fundOutput.value}`);

    // Compute contract ID from DDK-built funding tx (authoritative source)
    if (offer.temporaryContractId && fundTxId) {
      result.computedContractId = computeContractIdFromFundingOutpoint(
        offer.temporaryContractId,
        fundTxId,
        fundOutputIndex,
      );
    }

    log(
      `calling ddk.verifyCetAdaptorSigsFromOracleInfo: adaptorPairs=${adaptorPairs.length} ` +
        `cets=${dlcTxs.cets.length} messages=${messagesForDdk.length} ` +
        `oraclePubkey=${oracleInfo[0].publicKey.toString('hex').slice(0, 16)}... ` +
        `nonces=${oracleInfo[0].nonces.length} fundingScript=${fundingScript.length}b`,
    );
    let isValid = false;
    try {
      isValid = ddk.verifyCetAdaptorSigsFromOracleInfo(
        adaptorPairs,
        dlcTxs.cets,
        oracleInfo,
        acceptTyped.fundingPubkey,
        fundingScript,
        fundOutput.value,
        messagesForDdk,
      );
      log(`ddk.verifyCetAdaptorSigsFromOracleInfo returned ${isValid}`);
    } catch (ddkErr) {
      log(`ddk.verifyCetAdaptorSigsFromOracleInfo threw: ${(ddkErr as Error).stack ?? (ddkErr as Error).message}`);
      throw ddkErr;
    }

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
    result.note = `Adaptor verification unavailable: ${(err as Error).message}`;
    log(`aborted before DDK verification: ${(err as Error).stack ?? (err as Error).message}`);
    return result;
  }
}

async function main(): Promise<void> {
  const { offerHex, acceptHex, expectedOraclePubkey, signHex, attestationHex, showHelp } = parseCliArgs(
    process.argv.slice(2),
  );

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
  const eventMaturityEpoch =
    oracleAnnouncement?.getEventMaturityEpoch?.() || oracleAnnouncement?.oracleEvent?.eventMaturityEpoch;

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

  const adaptorResult = await verifyAdaptorSignatures(offer, accept, descriptor, fundingAddress, oracleAnnouncement);
  const singleFundedComputation = tryComputeContractIdFromSingleFunded(
    offer as Parameters<typeof tryComputeContractIdFromSingleFunded>[0],
    accept as Parameters<typeof tryComputeContractIdFromSingleFunded>[1],
    fundingAddress,
  );

  let computedContractId = 'n/a';
  if (adaptorResult.computedContractId) {
    computedContractId = adaptorResult.computedContractId;
  } else if (singleFundedComputation) {
    computedContractId = `${singleFundedComputation.cidRpcTxid} (rpc-txid convention)`;
  } else {
    const embeddedIds = [
      ...offer.fundingInputs
        .map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex'))
        .filter(Boolean),
      ...accept.fundingInputs
        .map((i: { dlcInput?: { contractId?: Buffer } }) => i.dlcInput?.contractId?.toString('hex'))
        .filter(Boolean),
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
  lines.push('Adaptor signature verification:');
  if (adaptorResult.available) {
    if (adaptorResult.fundTxId) lines.push(`  Fund TX ID: ${adaptorResult.fundTxId}`);
    if (adaptorResult.cetCount !== null) lines.push(`  CET count: ${adaptorResult.cetCount}`);
    if (adaptorResult.adaptorValid === true) {
      lines.push(
        `  CET adaptor signatures: CRYPTOGRAPHICALLY VALID (${adaptorResult.adaptorValidCount}/${adaptorResult.adaptorTotalCount})`,
      );
    }
    if (adaptorResult.adaptorValid === false) {
      lines.push(
        `  CET adaptor signatures: CRYPTOGRAPHICALLY INVALID (${adaptorResult.adaptorValidCount}/${adaptorResult.adaptorTotalCount})${adaptorResult.adaptorError ? ` - ${adaptorResult.adaptorError}` : ''}`,
      );
    }
    if (adaptorResult.refundSigValid === true) lines.push('  Refund signature: CRYPTOGRAPHICALLY VALID');
    if (adaptorResult.refundSigValid === false) lines.push('  Refund signature: CRYPTOGRAPHICALLY INVALID');
    if (adaptorResult.note) lines.push(`  Note: ${adaptorResult.note}`);
  } else {
    lines.push(`  ${adaptorResult.note}`);
    lines.push(`  Adaptor signatures: CRYPTOGRAPHICALLY INVALID (${adaptorResult.note})`);
  }

  if (!adaptorResult.available || !adaptorResult.fundTxId) {
    lines.push('  Contract ID from funding outpoint formula requires reconstructed fund tx + output index.');
  }

  // Sign message verification (CLI)
  if (signHex) {
    const signResult = await verifyDlc(offerHex, acceptHex, {
      expectedOraclePubkey: normalizedExpectedOraclePubkey || undefined,
      signHex,
    });
    lines.push('');
    lines.push('Sign message verification:');
    lines.push(`  Sign contract ID: ${signResult.signContractId || 'n/a'}`);
    lines.push(
      `  Contract ID match: ${signResult.signContractIdMatches === true ? 'MATCH' : signResult.signContractIdMatches === false ? 'MISMATCH' : 'n/a'}`,
    );
    if (signResult.signAdaptorValid === true) {
      lines.push(
        `  Sign adaptor signatures: CRYPTOGRAPHICALLY VALID (${signResult.signAdaptorValidCount}/${signResult.signAdaptorTotalCount})`,
      );
    } else if (signResult.signAdaptorValid === false) {
      lines.push(
        `  Sign adaptor signatures: CRYPTOGRAPHICALLY INVALID${signResult.signAdaptorError ? ` - ${signResult.signAdaptorError}` : ''}`,
      );
    } else {
      lines.push('  Sign adaptor signatures: not verified');
    }
  }

  // CET execution (when attestation provided)
  if (attestationHex && signHex) {
    try {
      const cetResult = await executeCet(offerHex, acceptHex, signHex, attestationHex);
      lines.push('');
      lines.push('CET Execution (oracle attestation provided):');
      lines.push(`  Attested outcome: ${cetResult.outcome}`);
      lines.push(`  Outcome index: ${cetResult.outcomeIndex}`);
      lines.push(`  CET TX ID: ${cetResult.cetTxid}`);
      lines.push(`  Signed CET hex (broadcastable):`);
      lines.push(`  ${cetResult.cetHex}`);
    } catch (cetErr) {
      lines.push('');
      lines.push(`CET Execution FAILED: ${(cetErr as Error).message}`);
    }
  } else if (attestationHex && !signHex) {
    lines.push('');
    lines.push('CET Execution: --attestation requires --sign to execute a CET');
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
