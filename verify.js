const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const { verify, math } = require('bip-schnorr');
const { BitcoinNetworks, chainHashFromNetwork } = require('bitcoin-networks');
const { DlcTxBuilder } = require('@node-dlc/core');
const {
  DlcOffer,
  DlcAccept,
  EnumeratedDescriptor,
  NumericalDescriptor,
  SingleOracleInfo,
  MultiOracleInfo,
} = require('@node-dlc/messaging');

const OFFER_HEX = `
a71a000000010006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f75e8f015ca87424c5fd51da4c15ba8e49d0626c64e27f9a55d0c42a94285216b000000000000004e200004086e6f742d706169640000000000004e20067265706169640000000000004e201d6c6971756964617465642d62792d6d617475726174696f6e2d6461746500000000000000001d6c6971756964617465642d62792d70726963652d7468726573686f6c64000000000000000000fdd824fd012a18c141dd421bb8c54e2965f964b9c53c30e2f8c288e84684d2da313fb314a16b3a739b951ab043c9a9b012c972c542ec4533cbab53ae597ff7b1cbd2b57e26dd8731249d979def2d5d76c61795969e953807d37ff36ef8dbab60d57ae08bb004fdd822c60001aaf6f439e22ebc287b0b72e45d62c2a6fc10392bd6e67b0fed7a5c0623cd909869ca9e00fdd8064e0004086e6f742d70616964067265706169641d6c6971756964617465642d62792d6d617475726174696f6e2d646174651d6c6971756964617465642d62792d70726963652d7468726573686f6c644d6c6f616e2d6d6174757265642d37393332653463326635313336636133643833653530373938373662643139333131626236316462336534306533323865346531386333386362316433343532036eb76057911e044f21ff936e44d559e50e8205115b398873663062978d59ca5300160014c4c19bd65e8e01887b4233d3d00aeba814e32e700000000000002e6c0000000000004e2001000000000000f93beb02000000000101e39ded02db3a29b96516add32332f14a90564b5003c69b019007127caa0984780100000000ffffffff026c5000000000000022002094dc89c4908b2b6e77240a7aef9bf348305ef5747eb9295e72dd9f84b61ce030c6d2120000000000160014a1ce41748ea25502e2b8a96b9f355d9f127d6650024830450221008adea390dbe7eed07f75e658c09796bce58a20d055613a012fcf52bacf38f2f90220708568036845fff6dac50103141b64dfa1fa5d9d399861f18ff4357e1fb4419001210384c27feb59925d4fab7a109e819359593a4024805a8aaddb2e36eefbe50f2a2b0000000000000001ffffffff006c000000001600140aaf7cb8008f5ad8869e13f47f490d4cc1e2870a00000000004f3700000000000005069e00000000000000036954661469d3d880
`.replace(/\s+/g, '');

const ACCEPT_HEX = `
a71c0000000175e8f015ca87424c5fd51da4c15ba8e49d0626c64e27f9a55d0c42a94285216b000000000000000003903300005c2442e25c16cc27491e27cac1f694873c66f3754290be363909378c001600146ca95318f13155e107ecaee89be880f614885154f9ba97c4a58d90c200001600146ca95318f13155e107ecaee89be880f61488515420ce87964a55e5520402d6976bff43f6db838aee8b7fe8bd3fa9e2c4d1c93cd713ba3f17a13230c6067403175812ef0fcf9577c3ded949c35269c2fb1d366708e03c4edd2e2bb3943e40b26048bf4f26e6cae095802ae112b1296ec9a13831f445b37081c362c4aa3542dbdfa78a978a17d7b8bd183ec83220d9714d584ce2d4a2cff316bfdc49681781e00b1cee98438bd63ecc6f225fcd7c9cfabe0ba98af13609112547f6d67ab30c4e02966e83473db580ddbabc8fda1d62074b08d823aee5e3013430449e2ebf3dd48903929a9152dec88ff9c1cd459554255c0d7f6862f8060c40520b74555afaedeb9a6567a37882ac4f5f3ed6ef194e74ceda88fde0e2d90423115b77459a880b6615004b50141972be52af0a569afe8014d87efdf26b03af8044fb349e48ec10f6afdd2fac90ab762ba82c28f0f1a35b753d5e72650e93b78281d0c7f27df2c3960d03602d3114d3c3d9cd672aa2730806545ee376afa8cb9a5e6cd150d9d952e5da6002552536cec0b25ee6338f6a261d43777f21993c356da47d048a3271d1936be3e5bb92908f150d1b29f0b6e4eb090f4b9c608d9aa32c3b9c96b9b247cbf0982abfffc62bcec688b7599d84e897694c4623d53aeecd4dc72b95c1a0916961d52abdf43e22b1ad91e665db410416b4f20a1d5a16e6a778b3c81e67c1944bd9db988f0383ba2802beda6a21f64a4356c61252491ded76986ae50177d35971b18adaf008029b63359f180780ecb6f34183e50482d2eb7bcc4ad4c266d3cd33e8668bcdb29284080ab6a48301d5bd5eafbf80de2092dd26f809ea5ee9caf869f4acb6ac5ac47b8742bed7ab95e82a3dbb91e82436cdd8f42b5ea2c449bf353090bec7e95cfc0b8f54d611373ea9e3e7824cf64d864c4890d994d0e9caa592ba68ebf56b55ef70889ae3043986cdfff2051c1c6521225583ca6a5b3c6ed81c02a32b81d98e5424fef0ab2b94ddc01da104a53e04074c864f4f3d2364a1fadee0620d4d9923f100
`.replace(/\s+/g, '');

const LOCKTIME_THRESHOLD = 500000000;

function satsToBtc(sats) {
  return (Number(sats) / 1e8).toFixed(8);
}

function amountFmt(sats) {
  return `${satsToBtc(sats)} BTC (${sats} sats)`;
}

function locktimeToHuman(locktime) {
  if (locktime >= LOCKTIME_THRESHOLD) {
    return `${new Date(locktime * 1000).toISOString()} UTC`;
  }
  return `block height ${locktime}`;
}

function detectNetwork(chainHash) {
  const entries = Object.values(BitcoinNetworks);
  for (const net of entries) {
    if (chainHash.equals(chainHashFromNetwork(net))) {
      return net;
    }
  }
  return BitcoinNetworks.bitcoin_regtest;
}

function extractContractInfo(contractInfo) {
  if (contractInfo.contractDescriptor) {
    return {
      descriptor: contractInfo.contractDescriptor,
      oracleInfo: contractInfo.oracleInfo,
      totalCollateral: contractInfo.totalCollateral,
      kind: 'single',
    };
  }

  const firstPair = contractInfo.contractOraclePairs?.[0];
  return {
    descriptor: firstPair?.contractDescriptor,
    oracleInfo: firstPair?.oracleInfo,
    totalCollateral: contractInfo.totalCollateral,
    kind: 'disjoint',
  };
}

function extractOracleAnnouncement(oracleInfo) {
  if (oracleInfo instanceof SingleOracleInfo) return oracleInfo.announcement;
  if (oracleInfo instanceof MultiOracleInfo) return oracleInfo.announcements?.[0];
  if (oracleInfo?.announcement) return oracleInfo.announcement;
  if (oracleInfo?.announcements?.length) return oracleInfo.announcements[0];
  return null;
}

function buildFundingInputsReport(inputs) {
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

function reconstructFundingAddress(offerFundingPubkey, acceptFundingPubkey, network) {
  const pubkeys = [offerFundingPubkey, acceptFundingPubkey].sort(Buffer.compare);
  const p2ms = bitcoin.payments.p2ms({ m: 2, pubkeys, network });
  const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms, network });

  return {
    address: p2wsh.address,
    witnessScriptHex: p2ms.output ? Buffer.from(p2ms.output).toString('hex') : 'n/a',
    scriptPubKeyHex: p2wsh.output ? Buffer.from(p2wsh.output).toString('hex') : null,
  };
}

function computeContractIdFromFundingOutpoint(tempContractId, fundTxIdHex, fundOutputIndex) {
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

function estimateSingleFundedFee(offer, inCount, outCount, hasWitness) {
  const varIntSize = (n) => (n < 0xfd ? 1 : 3);
  const inputBaseSize = offer.fundingInputs.reduce(
    (sum, input) => sum + 32 + 4 + varIntSize(input.scriptSigLength()) + input.scriptSigLength() + 4,
    0,
  );
  const outputScripts = [
    { serialId: offer.fundOutputSerialId, scriptHex: null },
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
    varIntSize(outCount) +
    outputBaseSize +
    4; // locktime

  const witnessSize =
    (hasWitness ? 2 : 0) +
    offer.fundingInputs.reduce((sum, input) => sum + input.maxWitnessLen, 0);

  const vbytes = Math.ceil((strippedSize * 4 + witnessSize) / 4);
  return BigInt(vbytes) * offer.feeRatePerVb;
}

function tryComputeContractIdFromSingleFunded(offer, accept, fundingAddress, feeOverride) {
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
    } catch (_) {
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
      kind: 'fund',
    },
    {
      serialId: offer.changeSerialId,
      value: offerChange,
      scriptHex: offer.changeSpk.toString('hex'),
      kind: 'change',
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

function buildCetTxHexes(offer, accept, descriptor, fundTxId, fundOutputIndex) {
  if (!(descriptor instanceof EnumeratedDescriptor)) return [];

  const cets = [];
  const outcomes = descriptor.outcomes || [];
  const totalCollateral = offer.contractInfo.totalCollateral;
  const offerSerial = offer.payoutSerialId;
  const acceptSerial = accept.payoutSerialId;

  for (const outcome of outcomes) {
    const offerPayout = outcome.localPayout;
    const acceptPayout = totalCollateral - offerPayout;
    const outputs = [];
    if (offerPayout > 0n) {
      outputs.push({
        serialId: offerSerial,
        value: offerPayout,
        script: offer.payoutSpk,
      });
    }
    if (acceptPayout > 0n) {
      outputs.push({
        serialId: acceptSerial,
        value: acceptPayout,
        script: accept.payoutSpk,
      });
    }
    outputs.sort((a, b) => (a.serialId < b.serialId ? -1 : 1));

    const tx = new bitcoin.Transaction();
    tx.version = 2;
    tx.locktime = offer.cetLocktime;
    tx.addInput(Buffer.from(fundTxId, 'hex').reverse(), fundOutputIndex, 0xfffffffe, Buffer.alloc(0));
    for (const output of outputs) {
      tx.addOutput(Buffer.from(output.script), BigInt(output.value));
    }
    cets.push(tx.toHex());
  }

  return cets;
}

async function initCfd() {
  // Tier 2 now uses DDK (ddk-ts native binary) for adaptor sig verification.
  // Probe for ddk-ts native binary (arm64 or x64)
  const ddkPaths = [
    path.join(__dirname, 'node_modules/@bennyblader/ddk-ts/dist/ddk-ts.darwin-arm64.node'),
    path.join(__dirname, 'node_modules/@bennyblader/ddk-ts/dist/ddk-ts.darwin-x64.node'),
    path.join(__dirname, 'node_modules/@bennyblader/ddk-ts/dist/ddk-ts.linux-x64-gnu.node'),
  ];
  // Also check orange-grove's pnpm store as fallback
  const ogDdkPath = path.resolve(__dirname, '../lygos/orange-grove/node_modules/.pnpm/@bennyblader+ddk-ts@0.3.32/node_modules/@bennyblader/ddk-ts/dist/ddk-ts.darwin-arm64.node');
  ddkPaths.push(ogDdkPath);

  for (const ddkPath of ddkPaths) {
    if (!fs.existsSync(ddkPath)) continue;
    const m = { exports: {} };
    process.dlopen(m, ddkPath);
    return m.exports;
  }

  throw new Error('Could not find ddk-ts native binary for Tier 2 verification');
}

function getTaggedOutcomeHash(outcomeText) {
  const tag = Buffer.from('DLC/oracle/attestation/v0', 'utf8');
  const tagHash = crypto.createHash('sha256').update(tag).digest();
  const outcomeBytes = Buffer.from(outcomeText, 'utf8');
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([tagHash, tagHash, outcomeBytes]))
    .digest();
}

async function tryTier2(offer, accept, descriptor, fundingAddress, oracleAnnouncement) {
  const result = {
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
    const ddk = await initCfd(); // now returns ddk-ts native module
    if (!(descriptor instanceof EnumeratedDescriptor)) {
      throw new Error('Tier 2 currently supports EnumeratedDescriptor contracts only');
    }

    if (!oracleAnnouncement?.oraclePublicKey || !oracleAnnouncement?.oracleEvent?.oracleNonces?.length) {
      throw new Error('Missing oracle announcement pubkey/nonce for adaptor verification');
    }

    // Build DLC transactions via DDK (deterministic reconstruction)
    const outcomes = descriptor.outcomes.map((o) => ({
      offer: BigInt(o.localPayout),
      accept: BigInt(offer.contractInfo.totalCollateral) - BigInt(o.localPayout),
    }));

    const fi = offer.fundingInputs[0];
    // CRITICAL: use toString() for display-order txid, NOT toString('hex')
    const localParams = {
      fundPubkey: offer.fundingPubkey,
      changeScriptPubkey: offer.changeSpk,
      changeSerialId: BigInt(offer.changeSerialId),
      payoutScriptPubkey: offer.payoutSpk,
      payoutSerialId: BigInt(offer.payoutSerialId),
      inputs: [{
        txid: fi.prevTx.txId.toString(),
        vout: fi.prevTxVout,
        scriptSig: Buffer.alloc(0),
        maxWitnessLength: fi.maxWitnessLen,
        serialId: BigInt(fi.inputSerialId),
      }],
      inputAmount: BigInt(fi.prevTx.outputs[fi.prevTxVout].value.sats),
      collateral: BigInt(offer.offerCollateral),
      dlcInputs: [],
    };

    // Build remote params (accepter may have 0 collateral in single-funded model)
    const remoteInputs = accept.fundingInputs.map((afi) => ({
      txid: afi.prevTx.txId.toString(),
      vout: afi.prevTxVout,
      scriptSig: Buffer.alloc(0),
      maxWitnessLength: afi.maxWitnessLen,
      serialId: BigInt(afi.inputSerialId),
    }));
    const remoteInputAmount = accept.fundingInputs.reduce(
      (sum, afi) => sum + BigInt(afi.prevTx.outputs[afi.prevTxVout].value.sats),
      0n,
    );
    const remoteParams = {
      fundPubkey: accept.fundingPubkey,
      changeScriptPubkey: accept.changeSpk,
      changeSerialId: BigInt(accept.changeSerialId),
      payoutScriptPubkey: accept.payoutSpk,
      payoutSerialId: BigInt(accept.payoutSerialId),
      inputs: remoteInputs,
      inputAmount: remoteInputAmount,
      collateral: BigInt(accept.acceptCollateral),
      dlcInputs: [],
    };

    const dlcTxs = ddk.createDlcTransactions(
      outcomes, localParams, remoteParams,
      offer.refundLocktime, BigInt(offer.feeRatePerVb), 0,
      offer.cetLocktime, BigInt(offer.fundOutputSerialId),
    );

    // Compute fund txid from DDK-built fund transaction
    const fundTxId = crypto
      .createHash('sha256')
      .update(crypto.createHash('sha256').update(dlcTxs.fund.rawBytes).digest())
      .digest()
      .reverse()
      .toString('hex');

    // Build tagged attestation messages: Array<Array<Array<Buffer>>> (per-CET → per-oracle → msgs)
    const messagesForDdk = descriptor.outcomes.map((o) => [[getTaggedOutcomeHash(o.outcome)]]);

    // Funding script: 2-of-2 P2MS in lexicographic pubkey order
    const pubkeys = Buffer.compare(offer.fundingPubkey, accept.fundingPubkey) < 0
      ? [offer.fundingPubkey, accept.fundingPubkey]
      : [accept.fundingPubkey, offer.fundingPubkey];
    const p2ms = bitcoin.payments.p2ms({ m: 2, pubkeys });

    const oracleInfo = [{
      publicKey: oracleAnnouncement.oraclePublicKey,
      nonces: oracleAnnouncement.oracleEvent.oracleNonces,
    }];

    // Adaptor pairs: for enum contracts, concat encryptedSig + dleqProof into signature field
    const adaptorSigs = accept.cetAdaptorSignatures?.sigs || accept.cetAdaptorSignatures || [];
    const adaptorPairs = adaptorSigs.map((sig) => ({
      signature: Buffer.concat([sig.encryptedSig, sig.dleqProof]),
      proof: Buffer.from(''),
    }));

    const fundOutputValue = dlcTxs.fund.outputs[0].value;

    const isValid = ddk.verifyCetAdaptorSigsFromOracleInfo(
      adaptorPairs,
      dlcTxs.cets,
      oracleInfo,
      accept.fundingPubkey,
      p2ms.output,
      fundOutputValue,
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
    result.note = `Tier 2 unavailable: ${err.message}`;
    return result;
  }
}

async function main() {
  const offer = DlcOffer.deserialize(Buffer.from(OFFER_HEX, 'hex'));
  const accept = DlcAccept.deserialize(Buffer.from(ACCEPT_HEX, 'hex'));

  const contract = extractContractInfo(offer.contractInfo);
  const descriptor = contract.descriptor;
  const oracleAnnouncement = extractOracleAnnouncement(contract.oracleInfo);

  const totalCollateral = contract.totalCollateral;
  const offerCollateral = offer.offerCollateral;
  const acceptCollateral = accept.acceptCollateral;

  const network = detectNetwork(offer.chainHash);
  const fundingAddress = reconstructFundingAddress(offer.fundingPubkey, accept.fundingPubkey, network);

  let contractType = 'unknown';
  let outcomes = [];

  if (descriptor instanceof EnumeratedDescriptor) {
    contractType = 'Enumerated';
    outcomes = descriptor.outcomes.map((o) => ({
      label: o.outcome,
      offererSats: o.localPayout,
      accepterSats: totalCollateral - o.localPayout,
    }));
  } else if (descriptor instanceof NumericalDescriptor) {
    contractType = `Numerical (${descriptor.numDigits} digits)`;
  }

  const offerInputs = buildFundingInputsReport(offer.fundingInputs);
  const acceptInputs = buildFundingInputsReport(accept.fundingInputs);

  const oraclePubkey = oracleAnnouncement?.oraclePublicKey?.toString('hex') || 'n/a';
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
      oracleSigError = e.message;
    }
  }

  const tier2 = await tryTier2(offer, accept, descriptor, fundingAddress, oracleAnnouncement);
  const singleFundedComputation = tryComputeContractIdFromSingleFunded(offer, accept, fundingAddress);

  let computedContractId = 'n/a';
  if (tier2.computedContractId) {
    computedContractId = tier2.computedContractId;
  } else if (singleFundedComputation) {
    computedContractId = `${singleFundedComputation.cidRpcTxid} (rpc-txid convention)`;
  } else {
    const embeddedIds = [
      ...offer.fundingInputs.map((i) => i.dlcInput?.contractId?.toString('hex')).filter(Boolean),
      ...accept.fundingInputs.map((i) => i.dlcInput?.contractId?.toString('hex')).filter(Boolean),
    ];
    if (embeddedIds.length > 0) {
      const unique = [...new Set(embeddedIds)];
      computedContractId = unique.length === 1
        ? `${unique[0]} (from embedded DlcInput)`
        : `${unique.join(', ')} (embedded DlcInput values differ)`;
    }
  }

  const lines = [];
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
  lines.push(`Oracle event ID: ${oracleEventId}`);
  lines.push(`Oracle announcement Schnorr signature: ${oracleSigValid ? 'valid' : `invalid (${oracleSigError})`}`);
  lines.push(`Loan maturity date: ${locktimeToHuman(offer.cetLocktime)}${eventMaturityEpoch ? ` (oracle event maturity: ${locktimeToHuman(eventMaturityEpoch)})` : ''}`);
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

main();
