export interface OutcomeInfo {
  label: string;
  offererSats: string;
  accepterSats: string;
}

export interface FundingInput {
  outpoint: string;
  sats: string | null;
}

export interface VerificationResult {
  // Tier 1 - Structural verification
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
  cetLocktime: number | null;
  refundLocktime: number | null;
  feeRatePerVb: string | null;
  offererFundingPubkey: string | null;
  accepterFundingPubkey: string | null;
  fundingAddress: string | null;
  witnessScript: string | null;
  offerInputs: FundingInput[];
  acceptInputs: FundingInput[];
  contractId: string | null;

  // Tier 2 - Cryptographic verification
  tier2Available: boolean;
  tier2Note: string | null;
  fundTxId: string | null;
  cetCount: number | null;
  adaptorValid: boolean | null;
  adaptorValidCount: number;
  adaptorTotalCount: number;
  adaptorError: string | null;

  // Tier 3 - Sign message verification (when sign hex provided)
  signAvailable: boolean;
  signContractId: string | null;
  signContractIdMatches: boolean | null;
  signAdaptorValid: boolean | null;
  signAdaptorValidCount: number;
  signAdaptorTotalCount: number;
  signAdaptorError: string | null;

  // Errors
  error: string | null;
}

export interface Tier2Result {
  available: boolean;
  note: string;
  fundTxId: string | null;
  cetCount: number | null;
  adaptorValid: boolean | null;
  adaptorValidCount: number;
  adaptorTotalCount: number;
  adaptorError: string | null;
  refundSigValid: boolean | null;
  computedContractId: string | null;
}

export interface VerifyOptions {
  expectedOraclePubkey?: string;
  signHex?: string;
}

export interface CliArgs {
  offerHex: string;
  acceptHex: string;
  expectedOraclePubkey: string | null;
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
}

export interface CetInfo {
  rawBytes: Buffer;
}
