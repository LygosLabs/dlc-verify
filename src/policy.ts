import * as crypto from 'node:crypto';
import type { VerificationResult } from './types';
import { verifyDlc } from './verify';

export type DlcPartyRole = 'offerer' | 'accepter';

export interface OracleEventPreimage {
  eventType: string;
  loanId: string;
  repaymentAddress: string;
  repaymentAmount: string;
}

export type OracleEventExpectation = { expectedEventId: string } | { eventIdPreimage: OracleEventPreimage };

export interface ExpectedLenderOutcome {
  outcome: string;
  lenderPayoutSats: string;
}

export interface DlcVerificationPolicy {
  lenderRole: DlcPartyRole;
  network: 'mainnet' | 'testnet' | 'regtest';
  expectedOraclePubkey: string;
  expectedLenderFundingPubkey: string;
  expectedLenderPayoutAddress: string;
  expectedTotalCollateralSats: string;
  oracleEvent: OracleEventExpectation;
  expectedCetLocktime?: number;
  expectedRefundLocktime?: number;
  expectedLenderOutcomes?: ExpectedLenderOutcome[];
}

export interface PolicyCheck {
  id: string;
  status: 'pass' | 'fail';
  expected: unknown;
  actual: unknown;
}

export interface TvcAttestationPayload {
  schemaVersion: 'lygos.dlc-verification.v1';
  verdict: 'pass' | 'fail';
  transcriptHash: string;
  policyHash: string;
  contractId: string | null;
  fundingTxId: string | null;
  fundOutputIndex: number | null;
  fundingValueSats: string | null;
  totalCollateralSats: string | null;
  oraclePubkey: string | null;
  oracleEventId: string | null;
  lenderFundingPubkey: string | null;
  lenderPayoutAddress: string | null;
  refundTxId: string | null;
  cetTxids: Array<{ outcome: string; txid: string }>;
}

export interface TvcVerificationResult {
  verdict: 'pass' | 'fail';
  checks: PolicyCheck[];
  verificationDigest: string;
  attestationPayload: TvcAttestationPayload;
  verification: VerificationResult;
}

function normalizeHex(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, '');
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, stableValue(child)]),
    );
  }
  return value;
}

function sha256Canonical(value: unknown): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(stableValue(value)))
    .digest('hex');
}

/** Matches packages/workflows/create-loan/event-id.ts in LygosLabs/chainlink-oracle. */
export function deriveLygosOracleEventId(input: OracleEventPreimage): string {
  const eventType = input.eventType.trim();
  const payload = [eventType, input.loanId.trim(), input.repaymentAddress.trim(), input.repaymentAmount.trim()].join(
    '//',
  );
  const hash = crypto.createHash('sha256').update(Buffer.from(payload, 'utf8')).digest('hex');
  return `${eventType}-${hash}`;
}

function expectedEventId(expectation: OracleEventExpectation): string {
  if ('expectedEventId' in expectation) return expectation.expectedEventId.trim();
  return deriveLygosOracleEventId(expectation.eventIdPreimage);
}

function addCheck(checks: PolicyCheck[], id: string, expected: unknown, actual: unknown): void {
  checks.push({
    id,
    status: JSON.stringify(stableValue(actual)) === JSON.stringify(stableValue(expected)) ? 'pass' : 'fail',
    expected,
    actual,
  });
}

export function evaluateDlcPolicy(
  verification: VerificationResult,
  policy: DlcVerificationPolicy,
): TvcVerificationResult {
  const checks: PolicyCheck[] = [];
  const lenderFundingPubkey =
    policy.lenderRole === 'offerer' ? verification.offererFundingPubkey : verification.accepterFundingPubkey;
  const lenderPayoutAddress =
    policy.lenderRole === 'offerer' ? verification.offererPayoutAddress : verification.accepterPayoutAddress;

  addCheck(checks, 'cryptographic-verification', 'pass', verification.verificationStatus);
  addCheck(checks, 'network', policy.network, verification.chainHashNetwork);
  addCheck(
    checks,
    'oracle-pubkey',
    normalizeHex(policy.expectedOraclePubkey),
    verification.extractedOraclePubkey ? normalizeHex(verification.extractedOraclePubkey) : null,
  );
  addCheck(
    checks,
    'lender-funding-pubkey',
    normalizeHex(policy.expectedLenderFundingPubkey),
    lenderFundingPubkey ? normalizeHex(lenderFundingPubkey) : null,
  );
  addCheck(checks, 'lender-payout-address', policy.expectedLenderPayoutAddress, lenderPayoutAddress);
  addCheck(
    checks,
    'refund-pays-lender-address',
    true,
    verification.refundOutputs.some((output) => output.address === policy.expectedLenderPayoutAddress),
  );
  addCheck(checks, 'total-collateral-sats', policy.expectedTotalCollateralSats, verification.totalCollateral);
  addCheck(checks, 'oracle-event-id', expectedEventId(policy.oracleEvent), verification.oracleEventId);

  if (policy.expectedCetLocktime !== undefined) {
    addCheck(checks, 'cet-locktime', policy.expectedCetLocktime, verification.cetLocktime);
  }
  if (policy.expectedRefundLocktime !== undefined) {
    addCheck(checks, 'refund-locktime', policy.expectedRefundLocktime, verification.refundLocktime);
  }

  for (const expectation of policy.expectedLenderOutcomes ?? []) {
    const outcome = verification.outcomes.find((candidate) => candidate.label === expectation.outcome);
    const actual = outcome ? (policy.lenderRole === 'offerer' ? outcome.offererSats : outcome.accepterSats) : null;
    addCheck(checks, `lender-outcome:${expectation.outcome}`, expectation.lenderPayoutSats, actual);
  }

  const verdict = checks.every((check) => check.status === 'pass') ? 'pass' : 'fail';
  const policyHash = sha256Canonical(policy);
  const attestationPayload: TvcAttestationPayload = {
    schemaVersion: 'lygos.dlc-verification.v1',
    verdict,
    transcriptHash: verification.transcriptHash,
    policyHash,
    contractId: verification.contractId,
    fundingTxId: verification.fundTxId,
    fundOutputIndex: verification.fundOutputIndex,
    fundingValueSats: verification.fundingValueSats,
    totalCollateralSats: verification.totalCollateral,
    oraclePubkey: verification.extractedOraclePubkey,
    oracleEventId: verification.oracleEventId,
    lenderFundingPubkey,
    lenderPayoutAddress,
    refundTxId: verification.refundTxId,
    cetTxids: verification.cets.map((cet) => ({ outcome: cet.outcome, txid: cet.txid })),
  };

  return {
    verdict,
    checks,
    verificationDigest: sha256Canonical(attestationPayload),
    attestationPayload,
    verification,
  };
}

export async function verifyDlcAgainstPolicy(
  offerHex: string,
  acceptHex: string,
  signHex: string,
  policy: DlcVerificationPolicy,
): Promise<TvcVerificationResult> {
  const verification = await verifyDlc(offerHex, acceptHex, {
    signHex,
    expectedOraclePubkey: policy.expectedOraclePubkey,
    network: policy.network,
  });
  return evaluateDlcPolicy(verification, policy);
}
