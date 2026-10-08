export interface OutcomeInfo {
  label: string;
  offererSats: string;
  accepterSats: string;
}

export interface FundingInput {
  outpoint: string;
  sats: string | null;
}

export interface TransactionOutputInfo {
  index: number;
  sats: string;
  scriptPubKey: string;
  address: string | null;
}

export interface CetTransactionInfo {
  outcome: string;
  txid: string;
  locktime: number;
  outputs: TransactionOutputInfo[];
}

export type VerificationStatus = 'pass' | 'fail' | 'incomplete';

export interface VerificationResult {
  // Network used to render addresses, and what the offer's chainHash claims
  // (null when the chainHash matches no known network). These can disagree.
  network: string;
  chainHashNetwork: string | null;

  // Structural verification (message parsing)
  contractType: string | null;
  totalCollateral: string | null;
  offerCollateral: string | null;
  acceptCollateral: string | null;
  outcomes: OutcomeInfo[];
  oraclePubkey: string | null;
  extractedOraclePubkey: string | null;
  expectedOraclePubkey: string | null;
  oraclePubkeySource: 'provided' | 'derived';
  oraclePubkeyMatchesExpected: boolean | null;
  oracleEventId: string | null;
  oracleSigValid: boolean;
  oracleSigError: string | null;
  // The oracle's signed event must list exactly the contract's outcome strings,
  // because the adaptor signatures are verified against those strings.
  oracleEventMatchesContract: boolean | null;
  oracleEventError: string | null;
  eventMaturityEpoch: number | null;
  cetLocktime: number | null;
  refundLocktime: number | null;
  // cetLocktime <= event maturity < refundLocktime, all as Unix times.
  locktimesValid: boolean | null;
  locktimeError: string | null;
  // contract_flags from the offer. Bit 0 sends the whole refund to the accepter.
  contractFlags: number | null;
  refundMode: 'each-party' | 'accepter' | null;
  contractFlagsError: string | null;
  // Every message must re-serialize to its input bytes with no unknown TLVs.
  canonicalEncoding: boolean | null;
  encodingError: string | null;
  feeRatePerVb: string | null;
  offererFundingPubkey: string | null;
  accepterFundingPubkey: string | null;
  fundingAddress: string | null;
  witnessScript: string | null;
  offererPayoutAddress: string | null;
  offererChangeAddress: string | null;
  accepterPayoutAddress: string | null;
  accepterChangeAddress: string | null;
  offerInputs: FundingInput[];
  acceptInputs: FundingInput[];
  contractId: string | null;

  // Deterministically reconstructed transaction facts
  transcriptHash: string;
  fundOutputIndex: number | null;
  fundingValueSats: string | null;
  refundTxId: string | null;
  refundOutputs: TransactionOutputInfo[];
  cets: CetTransactionInfo[];

  // Adaptor signature verification (cryptographic)
  adaptorSigVerificationAvailable: boolean;
  adaptorSigVerificationNote: string | null;
  fundTxId: string | null;
  cetCount: number | null;
  adaptorValid: boolean | null;
  adaptorValidCount: number;
  adaptorTotalCount: number;
  adaptorError: string | null;
  refundSigValid: boolean | null;
  refundSigError: string | null;

  // Sign message verification (when sign hex provided)
  signAvailable: boolean;
  signContractId: string | null;
  signContractIdMatches: boolean | null;
  signAdaptorValid: boolean | null;
  signAdaptorValidCount: number;
  signAdaptorTotalCount: number;
  signAdaptorError: string | null;
  signRefundSigValid: boolean | null;
  signRefundSigError: string | null;

  // Fail-closed summary for downstream verification consumers.
  verificationStatus: VerificationStatus;
  verificationFailures: string[];
  verificationIncomplete: string[];

  // Errors
  error: string | null;
}

export interface AdaptorVerificationResult {
  available: boolean;
  note: string;
  fundTxId: string | null;
  cetCount: number | null;
  adaptorValid: boolean | null;
  adaptorValidCount: number;
  adaptorTotalCount: number;
  adaptorError: string | null;
  refundSigValid: boolean | null;
  refundSigError: string | null;
  signAdaptorValid: boolean | null;
  signAdaptorValidCount: number;
  signAdaptorTotalCount: number;
  signAdaptorError: string | null;
  signRefundSigValid: boolean | null;
  signRefundSigError: string | null;
  computedContractId: string | null;
  fundOutputIndex: number | null;
  fundingValueSats: string | null;
  refundTxId: string | null;
  refundOutputs: TransactionOutputInfo[];
  cets: CetTransactionInfo[];
}

export interface VerifyOptions {
  expectedOraclePubkey?: string;
  signHex?: string;
  attestationHex?: string;
  logPrefix?: string;
  /** 'mainnet' | 'testnet' | 'regtest'. Unknown or absent falls back to mainnet. */
  network?: string;
}

export interface CetExecutionResult {
  cetHex: string;
  cetTxid: string;
  outcome: string;
  outcomeIndex: number;
}

export interface CliArgs {
  offerHex: string;
  acceptHex: string;
  expectedOraclePubkey: string | null;
  signHex: string | null;
  attestationHex: string | null;
  network: string;
  showHelp: boolean;
}

export interface SampleData {
  offer: string;
  accept: string;
}

export interface FundingAddressInfo {
  address: string | undefined;
  witnessScriptHex: string;
  scriptPubKeyHex: string | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface ContractInfo {
  // Using any for descriptor/oracleInfo since these come from external packages
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  descriptor: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  oracleInfo: any;
  totalCollateral: bigint;
  kind: 'single' | 'disjoint';
}

export interface SingleFundedComputation {
  fundTxId: string;
  fundOutputIndex: number;
  fee: bigint;
  offerChange: bigint;
  cidRpcTxid: string;
  cidInternalTxid: string;
}

export interface DdkModule {
  createDlcTransactions: (
    outcomes: Array<{ offer: bigint; accept: bigint }>,
    localParams: PartyParams,
    remoteParams: PartyParams,
    refundLocktime: number,
    feeRate: bigint,
    fundLocktime: number,
    cetLocktime: number,
    fundOutputSerialId: bigint,
    contractFlags: number,
  ) => DlcTransactions;
  verifyCetAdaptorSigsFromOracleInfo: (
    adaptorPairs: Array<{ signature: Buffer; proof: Buffer }>,
    cets: CetInfo[],
    oracleInfo: Array<{ publicKey: Buffer; nonces: Buffer[] }>,
    fundingPubkey: Buffer,
    fundingScript: Buffer,
    fundOutputValue: bigint,
    messages: Buffer[][][],
  ) => boolean;
  extractEcdsaSignatureFromOracleSignatures: (oracleSignatures: Buffer[], adaptorSignature: Buffer) => Buffer;
}

export interface PartyParams {
  fundPubkey: Buffer;
  changeScriptPubkey: Buffer;
  changeSerialId: bigint;
  payoutScriptPubkey: Buffer;
  payoutSerialId: bigint;
  inputs: PartyInput[];
  inputAmount: bigint;
  collateral: bigint;
  dlcInputs: unknown[];
}

export interface PartyInput {
  txid: string;
  vout: number;
  scriptSig: Buffer;
  maxWitnessLength: number;
  serialId: bigint;
}

export interface DlcTransactions {
  fund: {
    rawBytes: Buffer;
    outputs: Array<{ scriptPubkey?: Buffer; script?: Buffer; value: bigint }>;
  };
  cets: CetInfo[];
  refund: CetInfo;
}

export interface CetInfo {
  rawBytes: Buffer;
}
