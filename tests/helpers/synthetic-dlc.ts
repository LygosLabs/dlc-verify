/**
 * Synthetic DLC builder for tests.
 *
 * Builds complete, self-consistent Lygos-style loan transcripts (offer, accept,
 * sign) with freshly generated party keys and a freshly generated oracle, so a
 * test can change exactly one thing (an outcome string, the contract flags, a
 * locktime) and still hand the verifier genuinely signed messages. Everything
 * is offline: the funding input is borrowed from the sample fixture and is
 * never spent.
 */
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as bitcoin from 'bitcoinjs-lib';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const secp256k1 = require('secp256k1');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const schnorr = require('bip-schnorr');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { DlcOffer, DlcAccept, DlcSign, OracleAttestation, CetAdaptorSignatures } = require('@node-dlc/messaging');

export const SAMPLE_EVENT_MATURITY = 1774886400; // 2026-03-30T16:00:00Z, from examples/sample.json

interface Keypair {
  sk: Buffer;
  pk: Buffer;
}

function keypair(): Keypair {
  let sk: Buffer;
  do sk = crypto.randomBytes(32);
  while (!secp256k1.privateKeyVerify(sk));
  return { sk, pk: Buffer.from(secp256k1.publicKeyCreate(sk, true)) };
}

/** A secret key whose public key has even y, as BIP340 keys and nonces require. */
function xonlyKey(): { sk: Buffer; x: Buffer } {
  const { sk, pk } = keypair();
  const even = pk[0] === 0x02 ? sk : Buffer.from(secp256k1.privateKeyNegate(Buffer.from(sk)));
  return { sk: even, x: pk.subarray(1) };
}

const taggedHash = (tag: string, data: Buffer): Buffer => schnorr.math.taggedHash(tag, data);

/** BIP340 signature with an explicit nonce: s = k + e*x mod n. */
function bip340SignWithNonce(skEven: Buffer, kEven: Buffer, message32: Buffer): Buffer {
  const px = Buffer.from(secp256k1.publicKeyCreate(skEven, true)).subarray(1);
  const rx = Buffer.from(secp256k1.publicKeyCreate(kEven, true)).subarray(1);
  const e = taggedHash('BIP0340/challenge', Buffer.concat([rx, px, message32]));
  const ex = Buffer.from(secp256k1.privateKeyTweakMul(Buffer.from(skEven), e));
  const s = Buffer.from(secp256k1.privateKeyTweakAdd(ex, kEven));
  const sig = Buffer.concat([rx, s]);
  schnorr.verify(px, message32, sig);
  return sig;
}

export interface SyntheticOracle {
  pubkey: Buffer;
  nonce: Buffer;
  /** Attest an outcome under the announced nonce. */
  attest(outcome: string): Buffer;
  /** Attest an outcome under a fresh nonce the announcement never committed to. */
  attestWithFreshNonce(outcome: string): Buffer;
  signAnnouncement(oracleEvent: { serialize(): Buffer }): Buffer;
}

function makeOracle(): SyntheticOracle {
  const key = xonlyKey();
  const nonce = xonlyKey();
  const message = (outcome: string) => taggedHash('DLC/oracle/attestation/v0', Buffer.from(outcome, 'utf8'));
  return {
    pubkey: key.x,
    nonce: nonce.x,
    attest: (outcome) => bip340SignWithNonce(key.sk, nonce.sk, message(outcome)),
    attestWithFreshNonce: (outcome) => bip340SignWithNonce(key.sk, xonlyKey().sk, message(outcome)),
    signAnnouncement: (oracleEvent) =>
      Buffer.from(schnorr.sign(key.sk.toString('hex'), taggedHash('DLC/oracle/announcement/v0', oracleEvent.serialize()))),
  };
}

export function loadDdk(): any {
  const { platform, arch } = process;
  const target =
    platform === 'darwin' && arch === 'arm64'
      ? ['ddk-ts-darwin-arm64', 'ddk-ts.darwin-arm64.node']
      : platform === 'darwin' && arch === 'x64'
        ? ['ddk-ts-darwin-x64', 'ddk-ts.darwin-x64.node']
        : platform === 'linux' && arch === 'x64'
          ? ['ddk-ts-linux-x64-gnu', 'ddk-ts.linux-x64-gnu.node']
          : null;
  if (!target) throw new Error(`Unsupported platform for ddk-ts: ${platform}-${arch}`);
  const pkgDir = path.dirname(require.resolve('@bennyblader/ddk-ts/package.json'));
  const candidates = [path.join(pkgDir, '..', target[0], target[1]), path.join(pkgDir, 'dist', target[1])];
  const bin = candidates.find((c) => fs.existsSync(c));
  if (!bin) throw new Error(`ddk-ts native binary not found. Checked: ${candidates.join(', ')}`);
  const m = { exports: {} as any };
  process.dlopen(m, bin);
  return m.exports;
}

const ddk = loadDdk();

function loadExample(name: string): { offer: string; accept: string; sign?: string } {
  return JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../examples', name), 'utf8'));
}

const outcomeHash = (s: string): Buffer => taggedHash('DLC/oracle/attestation/v0', Buffer.from(s, 'utf8'));

function partyParams(m: any, inputs: any[], collateral: bigint) {
  return {
    fundPubkey: m.fundingPubkey,
    changeScriptPubkey: m.changeSpk,
    changeSerialId: BigInt(m.changeSerialId),
    payoutScriptPubkey: m.payoutSpk,
    payoutSerialId: BigInt(m.payoutSerialId),
    inputs: inputs.map((i) => ({
      txid: i.prevTx.txId.toString(),
      vout: i.prevTxVout,
      scriptSig: Buffer.alloc(0),
      maxWitnessLength: i.maxWitnessLen,
      serialId: BigInt(i.inputSerialId),
    })),
    inputAmount: inputs.reduce((s: bigint, i) => s + BigInt(i.prevTx.outputs[i.prevTxVout]?.value?.sats ?? 0n), 0n),
    collateral: BigInt(collateral),
    dlcInputs: [],
  };
}

function fundingScripts(offerPk: Buffer, acceptPk: Buffer): { script: Buffer; spk: Buffer } {
  const pubkeys = [offerPk, acceptPk].sort(Buffer.compare);
  const p2ms = bitcoin.payments.p2ms({ m: 2, pubkeys });
  const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms });
  return { script: Buffer.from(p2ms.output as Uint8Array), spk: Buffer.from(p2wsh.output as Uint8Array) };
}

export interface BuiltTxs {
  txs: any;
  fundTx: bitcoin.Transaction;
  fundVout: number;
  fundValue: bigint;
  fundingScript: Buffer;
}

/** Build fund/CETs/refund with DDK, honouring the contract flags. */
export function buildTxs(offer: any, accept: any, contractFlags: number): BuiltTxs {
  const d = offer.contractInfo.contractDescriptor;
  const total = BigInt(offer.contractInfo.totalCollateral);
  const outcomes = d.outcomes.map((o: any) => ({ offer: BigInt(o.localPayout), accept: total - BigInt(o.localPayout) }));
  const txs = ddk.createDlcTransactions(
    outcomes,
    partyParams(offer, offer.fundingInputs, offer.offerCollateral),
    partyParams(accept, accept.fundingInputs, accept.acceptCollateral),
    offer.refundLocktime,
    BigInt(offer.feeRatePerVb),
    0,
    offer.cetLocktime,
    BigInt(offer.fundOutputSerialId),
    contractFlags,
  );
  const scripts = fundingScripts(offer.fundingPubkey, accept.fundingPubkey);
  const fundTx = bitcoin.Transaction.fromBuffer(txs.fund.rawBytes);
  const fundVout = fundTx.outs.findIndex((o) => Buffer.from(o.script).equals(scripts.spk));
  if (fundVout < 0) throw new Error('fund output not found');
  return { txs, fundTx, fundVout, fundValue: BigInt(fundTx.outs[fundVout].value), fundingScript: scripts.script };
}

function contractIdFor(fundTx: bitcoin.Transaction, fundVout: number, tempId: Buffer): Buffer {
  const id = Buffer.from(fundTx.getId(), 'hex');
  id[30] ^= (fundVout >> 8) & 0xff;
  id[31] ^= fundVout & 0xff;
  for (let i = 0; i < 32; i++) id[i] ^= tempId[i];
  return id;
}

function adaptorSigs(built: BuiltTxs, outcomes: string[], oracle: SyntheticOracle, sk: Buffer): any {
  const sigs = ddk.createCetAdaptorSigsFromOracleInfo(
    built.txs.cets,
    [{ publicKey: oracle.pubkey, nonces: [oracle.nonce] }],
    sk,
    built.fundingScript,
    built.fundValue,
    outcomes.map((o) => [[outcomeHash(o)]]),
  );
  const cas = new CetAdaptorSignatures();
  cas.sigs = sigs.map((s: any) => {
    const full = Buffer.from(s.signature);
    if (full.length !== 162) throw new Error(`unexpected adaptor sig length ${full.length}`);
    return { encryptedSig: full.subarray(0, 65), dleqProof: full.subarray(65) };
  });
  return cas;
}

function refundSig(built: BuiltTxs, sk: Buffer): Buffer {
  const sighash = Buffer.from(ddk.getCetSighash(built.txs.refund, built.fundingScript, built.fundValue));
  return Buffer.from(secp256k1.ecdsaSign(sighash, sk).signature);
}

export interface SyntheticContractOptions {
  /** Outcomes the CETs and adaptor signatures encode. */
  contractOutcomes?: Array<{ outcome: string; localPayout: number | bigint }>;
  /** Outcomes the oracle's signed event lists (defaults to the contract's). */
  announcedOutcomes?: string[];
  /** Byte written into the offer's contract_flags. */
  contractFlags?: number;
  /** Flags used to build the transactions that get signed (defaults to contractFlags). */
  signFlags?: number;
  cetLocktime?: number;
  refundLocktime?: number;
  eventMaturityEpoch?: number;
  eventId?: string;
}

export interface SyntheticContract {
  offer: any;
  accept: any;
  sign: any;
  oracle: SyntheticOracle;
  offerer: Keypair;
  accepter: Keypair;
  built: BuiltTxs;
  contractOutcomes: string[];
  eventId: string;
  hex: { offer: string; accept: string; sign: string };
}

export function makeContract(opts: SyntheticContractOptions = {}): SyntheticContract {
  const sample = loadExample('sample.json');
  const signed = loadExample('testnet-loan-118c9fc9.json');
  const offer = DlcOffer.deserialize(Buffer.from(sample.offer, 'hex'));
  const accept = DlcAccept.deserialize(Buffer.from(sample.accept, 'hex'));
  const offerer = keypair();
  const accepter = keypair();
  const oracle = makeOracle();

  offer.fundingPubkey = offerer.pk;
  accept.fundingPubkey = accepter.pk;
  if (opts.cetLocktime !== undefined) offer.cetLocktime = opts.cetLocktime;
  if (opts.refundLocktime !== undefined) offer.refundLocktime = opts.refundLocktime;
  offer.contractFlags = Buffer.from([opts.contractFlags ?? 0]);

  const descriptor = offer.contractInfo.contractDescriptor;
  if (opts.contractOutcomes) {
    descriptor.outcomes = opts.contractOutcomes.map((o) => ({ outcome: o.outcome, localPayout: BigInt(o.localPayout) }));
  }
  const contractOutcomes: string[] = descriptor.outcomes.map((o: any) => o.outcome);

  const announcement = offer.contractInfo.oracleInfo.announcement;
  announcement.oraclePublicKey = oracle.pubkey;
  announcement.oracleEvent.oracleNonces = [oracle.nonce];
  announcement.oracleEvent.eventDescriptor.outcomes = opts.announcedOutcomes ?? contractOutcomes.slice();
  if (opts.eventMaturityEpoch !== undefined) announcement.oracleEvent.eventMaturityEpoch = opts.eventMaturityEpoch;
  if (opts.eventId !== undefined) announcement.oracleEvent.eventId = opts.eventId;
  announcement.announcementSig = oracle.signAnnouncement(announcement.oracleEvent);

  const built = buildTxs(offer, accept, opts.signFlags ?? opts.contractFlags ?? 0);
  accept.cetAdaptorSignatures = adaptorSigs(built, contractOutcomes, oracle, accepter.sk);
  accept.refundSignature = refundSig(built, accepter.sk);

  const sign = new DlcSign();
  sign.protocolVersion = 1;
  sign.contractId = contractIdFor(built.fundTx, built.fundVout, offer.temporaryContractId);
  sign.cetAdaptorSignatures = adaptorSigs(built, contractOutcomes, oracle, offerer.sk);
  sign.refundSignature = refundSig(built, offerer.sk);
  // Funding witnesses are not verified by dlc-verify; borrow a well-formed set.
  sign.fundingSignatures = DlcSign.deserialize(Buffer.from(signed.sign as string, 'hex')).fundingSignatures;

  return {
    offer,
    accept,
    sign,
    oracle,
    offerer,
    accepter,
    built,
    contractOutcomes,
    eventId: announcement.oracleEvent.eventId,
    hex: {
      offer: offer.serialize().toString('hex'),
      accept: accept.serialize().toString('hex'),
      sign: sign.serialize().toString('hex'),
    },
  };
}

/** A 64-byte value shaped like a BIP340 signature (valid curve x, random s) that signs nothing. */
export function bogusSignature(): Buffer {
  return Buffer.concat([xonlyKey().x, crypto.randomBytes(32)]);
}

export function attestationHex(oracle: SyntheticOracle, eventId: string, outcome: string, signature?: Buffer): string {
  const a = new OracleAttestation();
  a.eventId = eventId;
  a.oraclePublicKey = oracle.pubkey;
  a.signatures = [signature ?? oracle.attest(outcome)];
  a.outcomes = [outcome];
  return a.serialize().toString('hex');
}

/** Check both witness signatures of a fully signed CET against its sighash. */
export function cetWitnessValid(cetHex: string, built: BuiltTxs, offerPk: Buffer, acceptPk: Buffer): boolean {
  const tx = bitcoin.Transaction.fromHex(cetHex);
  const sighash = tx.hashForWitnessV0(0, built.fundingScript, built.fundValue, bitcoin.Transaction.SIGHASH_ALL);
  const witness = tx.ins[0].witness;
  const sigs = [witness[1], witness[2]].map((s) => Buffer.from(s).subarray(0, -1));
  return sigs.every((der) => {
    let compact: Uint8Array;
    try {
      compact = secp256k1.signatureImport(der);
    } catch {
      return false;
    }
    return [offerPk, acceptPk].some((pk) => secp256k1.ecdsaVerify(compact, sighash, pk));
  });
}

export function txOutputs(rawBytes: Buffer, network: bitcoin.Network): Array<{ sats: string; address: string | null }> {
  const tx = bitcoin.Transaction.fromBuffer(rawBytes);
  return tx.outs.map((o) => {
    let address: string | null = null;
    try {
      address = bitcoin.address.fromOutputScript(Buffer.from(o.script), network);
    } catch {}
    return { sats: String(o.value), address };
  });
}

export function payoutAddress(message: any, network: bitcoin.Network): string {
  return message.getAddresses(network).payoutAddress;
}
