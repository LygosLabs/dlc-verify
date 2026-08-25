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
  lenderRole?: DlcPartyRole;
  network?: 'mainnet' | 'testnet' | 'regtest';
  expectedOraclePubkey?: string;
  expectedLenderFundingPubkey?: string;
  expectedLenderPayoutAddress?: string;
  expectedTotalCollateralSats?: string;
  oracleEvent?: OracleEventExpectation;
  expectedCetLocktime?: number;
  expectedRefundLocktime?: number;
  expectedLenderOutcomes?: ExpectedLenderOutcome[];
}

export type PolicyCoverage = 'not_provided' | 'partial' | 'complete';
export type PolicyVerificationStatus = 'not_provided' | 'pass' | 'fail';
export type VerificationVerdict = 'pass' | 'fail' | 'incomplete';

export interface PolicyCheck {
  id: string;
  status: 'pass' | 'fail';
  expected: unknown;
  actual: unknown;
}

export interface VerificationAttestationPayload {
  schemaVersion: 'lygos.dlc-verification.v1';
  verdict: VerificationVerdict;
  cryptographicVerification: VerificationResult['verificationStatus'];
  policyVerification: PolicyVerificationStatus;
  policyCoverage: PolicyCoverage;
  transcriptHash: string;
  policyHash: string | null;
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

export interface DlcPolicyVerificationResult {
  verdict: VerificationVerdict;
  cryptographicVerification: VerificationResult['verificationStatus'];
  policyVerification: PolicyVerificationStatus;
  policyCoverage: PolicyCoverage;
  checks: PolicyCheck[];
  verificationDigest: string;
  attestationPayload: VerificationAttestationPayload;
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

/** Derives the Lygos loan oracle event ID from the canonical repayment-term preimage. */
export function deriveLygosOracleEventId(input: OracleEventPreimage): string {
  const eventType = input.eventType.trim();
  const payload = [eventType, input.loanId.trim(), input.repaymentAddress.trim(), input.repaymentAmount.trim()].join(
    '//',
  );
  const hash = crypto.createHash('sha256').update(Buffer.from(payload, 'utf8')).digest('hex');
  return `${eventType}-${hash}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function expectedEventId(expectation: unknown): string | null {
  if (!isRecord(expectation)) return null;
  if (isNonEmptyString(expectation.expectedEventId)) return expectation.expectedEventId.trim();

  const preimage = expectation.eventIdPreimage;
  if (!isRecord(preimage)) return null;
  const { eventType, loanId, repaymentAddress, repaymentAmount } = preimage;
  if (
    !isNonEmptyString(eventType) ||
    !isNonEmptyString(loanId) ||
    !isNonEmptyString(repaymentAddress) ||
    !isNonEmptyString(repaymentAmount)
  ) {
    return null;
  }

  return deriveLygosOracleEventId({ eventType, loanId, repaymentAddress, repaymentAmount });
}

function addCheck(checks: PolicyCheck[], id: string, expected: unknown, actual: unknown): void {
  checks.push({
    id,
    status: JSON.stringify(stableValue(actual)) === JSON.stringify(stableValue(expected)) ? 'pass' : 'fail',
    expected,
    actual,
  });
}

const COMPLETE_POLICY_FIELDS: Array<keyof DlcVerificationPolicy> = [
  'lenderRole',
  'network',
  'expectedOraclePubkey',
  'expectedLenderFundingPubkey',
  'expectedLenderPayoutAddress',
  'expectedTotalCollateralSats',
  'oracleEvent',
];

function hasValue(value: unknown): boolean {
  return value !== undefined && value !== null && value !== '';
}

function policyCoverage(policy: DlcVerificationPolicy | undefined): PolicyCoverage {
  if (!policy || !Object.values(policy).some(hasValue)) return 'not_provided';
  return COMPLETE_POLICY_FIELDS.every((field) => hasValue(policy[field])) ? 'complete' : 'partial';
}

export function evaluateDlcPolicy(
  verification: VerificationResult,
  policy?: DlcVerificationPolicy,
): DlcPolicyVerificationResult {
  const checks: PolicyCheck[] = [];
  const lenderFundingPubkey =
    policy?.lenderRole === 'offerer'
      ? verification.offererFundingPubkey
      : policy?.lenderRole === 'accepter'
        ? verification.accepterFundingPubkey
        : null;
  const lenderPayoutAddress =
    policy?.lenderRole === 'offerer'
      ? verification.offererPayoutAddress
      : policy?.lenderRole === 'accepter'
        ? verification.accepterPayoutAddress
        : null;

  if (policy?.network !== undefined) {
    addCheck(checks, 'network', policy.network, verification.network);
  }
  if (policy?.expectedOraclePubkey !== undefined) {
    addCheck(
      checks,
      'oracle-pubkey',
      normalizeHex(policy.expectedOraclePubkey),
      verification.extractedOraclePubkey ? normalizeHex(verification.extractedOraclePubkey) : null,
    );
  }
  if (policy?.expectedLenderFundingPubkey !== undefined) {
    addCheck(
      checks,
      'lender-funding-pubkey',
      normalizeHex(policy.expectedLenderFundingPubkey),
      lenderFundingPubkey ? normalizeHex(lenderFundingPubkey) : null,
    );
  }
  if (policy?.expectedLenderPayoutAddress !== undefined) {
    addCheck(checks, 'lender-payout-address', policy.expectedLenderPayoutAddress, lenderPayoutAddress);
    addCheck(
      checks,
      'refund-pays-lender-address',
      true,
      verification.refundOutputs.some((output) => output.address === policy.expectedLenderPayoutAddress),
    );
  }
  if (policy?.expectedTotalCollateralSats !== undefined) {
    addCheck(checks, 'total-collateral-sats', policy.expectedTotalCollateralSats, verification.totalCollateral);
  }
  if (policy?.oracleEvent !== undefined) {
    const expected = expectedEventId(policy.oracleEvent);
    if (expected === null) {
      checks.push({
        id: 'oracle-event-id',
        status: 'fail',
        expected: 'a non-empty expectedEventId or complete eventIdPreimage',
        actual: policy.oracleEvent,
      });
    } else {
      addCheck(checks, 'oracle-event-id', expected, verification.oracleEventId);
    }
  }
  if (policy?.expectedCetLocktime !== undefined) {
    addCheck(checks, 'cet-locktime', policy.expectedCetLocktime, verification.cetLocktime);
  }
  if (policy?.expectedRefundLocktime !== undefined) {
    addCheck(checks, 'refund-locktime', policy.expectedRefundLocktime, verification.refundLocktime);
  }

  for (const expectation of policy?.expectedLenderOutcomes ?? []) {
    const outcome = verification.outcomes.find((candidate) => candidate.label === expectation.outcome);
    const actual = outcome
      ? policy?.lenderRole === 'offerer'
        ? outcome.offererSats
        : policy?.lenderRole === 'accepter'
          ? outcome.accepterSats
          : null
      : null;
    addCheck(checks, `lender-outcome:${expectation.outcome}`, expectation.lenderPayoutSats, actual);
  }

  const coverage = policyCoverage(policy);
  const policyVerification: PolicyVerificationStatus =
    checks.length === 0 ? 'not_provided' : checks.every((check) => check.status === 'pass') ? 'pass' : 'fail';
  const cryptographicVerification = verification.verificationStatus;
  const verdict: VerificationVerdict =
    cryptographicVerification === 'fail' || policyVerification === 'fail'
      ? 'fail'
      : cryptographicVerification === 'pass' && coverage === 'complete' && policyVerification === 'pass'
        ? 'pass'
        : 'incomplete';
  const policyHash = coverage === 'not_provided' ? null : sha256Canonical(policy);
  const attestationPayload: VerificationAttestationPayload = {
    schemaVersion: 'lygos.dlc-verification.v1',
    verdict,
    cryptographicVerification,
    policyVerification,
    policyCoverage: coverage,
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
    cryptographicVerification,
    policyVerification,
    policyCoverage: coverage,
    checks,
    verificationDigest: sha256Canonical(attestationPayload),
    attestationPayload,
    verification,
  };
}

export async function verifyDlcAgainstPolicy(
  offerHex: string,
  acceptHex: string,
  signHex?: string,
  policy?: DlcVerificationPolicy,
  network?: string,
): Promise<DlcPolicyVerificationResult> {
  const verification = await verifyDlc(offerHex, acceptHex, {
    signHex,
    expectedOraclePubkey: policy?.expectedOraclePubkey,
    network: network ?? policy?.network,
  });
  return evaluateDlcPolicy(verification, policy);
}
