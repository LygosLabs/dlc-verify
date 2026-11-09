// Pure helpers for the page: building requests from the form and turning reports into text.
// Nothing here touches the DOM, so `node --test tools/web.test.mjs` can check it.

/** Formats an amount in satoshis: `100,000 sat`. */
export function sats(value) {
  return `${Number(value).toLocaleString('en-US')} sat`;
}

/** A script as a person reads it: its address, or its hex when it has none. */
export function scriptText(script) {
  if (!script) return '';
  return script.address ?? `${script.kind} script ${script.hex}`;
}

/** One output of a CET or refund: `third-party 100,000 sat to bcrt1q…`. */
export function outputText(output) {
  const to = output.payee === 'third-party' ? ` to ${scriptText(output.script)}` : '';
  return `${output.payee} ${sats(output.value_sat)}${to}`;
}

/** A locktime as the report gives it (`{value, kind, utc?}`). */
export function locktimeText(locktime) {
  if (!locktime) return '';
  switch (locktime.kind) {
    case 'none':
      return `${locktime.value} (no lock)`;
    case 'time':
      return locktime.utc ?? String(locktime.value);
    case 'height':
      return `block ${locktime.value.toLocaleString('en-US')}`;
    default:
      return String(locktime.value);
  }
}

/** Whether `text` is a JSON bundle rather than hex. */
export function isBundle(text) {
  return text.trimStart().startsWith('{');
}

/** Whether a bundle's text carries attestations `settle` can use without being given one. */
export function bundleHasAttestations(text) {
  if (!isBundle(text)) return false;
  try {
    const bundle = JSON.parse(text);
    return Array.isArray(bundle.attestations) && bundle.attestations.length > 0;
  } catch {
    return false;
  }
}

/** Strips whitespace from pasted hex, so line-wrapped hex still reads. */
export function compactHex(text) {
  return text.replace(/\s+/g, '');
}

/**
 * The messages part of a request, from the form.
 *
 * `mode` is `bundle` (one box: a JSON bundle or an offer in hex) or `separate` (one box per
 * message). Throws an `Error` saying what is missing.
 */
export function messagesRequest(mode, fields) {
  if (mode === 'bundle') {
    const text = (fields.bundle ?? '').trim();
    if (!text) throw new Error('Paste a bundle or an offer, or open a file.');
    return { input: isBundle(text) ? text : compactHex(text) };
  }
  const offer = compactHex(fields.offer ?? '');
  const accept = compactHex(fields.accept ?? '');
  const sign = compactHex(fields.sign ?? '');
  if (!offer) throw new Error('Paste the offer: the accept and sign are checked against it.');
  if (sign && !accept) throw new Error('A sign message needs the accept it answers.');
  const request = { offer };
  if (accept) request.accept = accept;
  if (sign) request.sign = sign;
  return request;
}

/**
 * The policy part of a verify request, from the form: nothing, a profile with optional terms, or
 * a policy file's text. Throws an `Error` saying what is missing.
 */
export function policyRequest(mode, fields) {
  switch (mode) {
    case 'profile': {
      if (!fields.profile) throw new Error('Choose a profile.');
      const terms = (fields.terms ?? '').trim();
      return terms ? { profile: fields.profile, terms } : { profile: fields.profile };
    }
    case 'policy': {
      const policy = (fields.policy ?? '').trim();
      if (!policy) throw new Error('Paste a policy file, or choose no policy.');
      return { policy };
    }
    default:
      return {};
  }
}

/** The attestations part of a settle request: what was pasted, or nothing for the bundle's own. */
export function attestationsRequest(text) {
  const trimmed = (text ?? '').trim();
  if (!trimmed) return {};
  const json = trimmed.startsWith('{') || trimmed.startsWith('[') || trimmed.startsWith('"');
  return { attestations: json ? trimmed : compactHex(trimmed) };
}

/** The headline for a report's status. */
export function verdict(report) {
  const { counts } = report;
  const tally = [
    `${counts.pass} passed`,
    counts.warn ? `${counts.warn} warned` : null,
    counts.fail ? `${counts.fail} failed` : null,
    counts.skip ? `${counts.skip} not run` : null,
  ]
    .filter(Boolean)
    .join(', ');
  switch (report.status) {
    case 'pass':
      return {
        title: 'Pass',
        detail: report.policy
          ? `The messages are consistent, every signature verifies, and the terms match the policy. ${tally}.`
          : `The messages are consistent and every signature verifies. ${tally}.`,
      };
    case 'fail':
      return {
        title: 'Fail',
        detail: `Do not rely on this contract until you understand every failure below. ${tally}.`,
      };
    default:
      return {
        title: 'Incomplete',
        detail: `Nothing failed, but some checks could not run: a message is missing, or a funding witness is not in the messages. ${tally}.`,
      };
  }
}

/** The contract overview as label and value rows. Values that are ids or keys are `mono`. */
export function contractRows(contract) {
  if (!contract) return [];
  const rows = [];
  const row = (label, value, mono = false) => {
    if (value !== undefined && value !== null && value !== '') rows.push({ label, value, mono });
  };
  row('Network', contract.network ?? 'unknown chain');
  row('Contract id', contract.contract_id, true);
  row('Temporary id', contract.temporary_contract_id, true);
  const accepter = contract.accepter ? `, accepter ${sats(contract.accepter.collateral_sat)}` : '';
  row(
    'Collateral',
    `${sats(contract.total_collateral_sat)}: offerer ${sats(contract.offerer.collateral_sat)}${accepter}`,
  );
  row(
    'Fee rate',
    `${contract.fee_rate_per_vb} sat/vB${contract.fee_rule ? `, CET fee rule ${contract.fee_rule}` : ''}`,
  );
  row('Flags', contract.contract_flags.length ? contract.contract_flags.join(', ') : 'none');
  if (contract.oracle_maturity) {
    const { earliest, latest } = contract.oracle_maturity;
    row(
      'Oracle maturity',
      earliest.unix === latest.unix ? earliest.utc : `${earliest.utc} to ${latest.utc}`,
    );
  }
  row('CET locktime', locktimeText(contract.cet_locktime));
  row('Refund locktime', locktimeText(contract.refund_locktime));
  if (contract.funding_output) {
    const { txid, vout, value_sat } = contract.funding_output;
    row('Funding output', `${txid}:${vout}, ${sats(value_sat)}`, true);
  }
  row('Offerer key', contract.offerer.funding_pubkey, true);
  row('Offerer pays to', scriptText(contract.offerer.payout), true);
  if (contract.accepter) {
    row('Accepter key', contract.accepter.funding_pubkey, true);
    row('Accepter pays to', scriptText(contract.accepter.payout), true);
  }
  for (const override of contract.payout_overrides) {
    row('Third party', `${scriptText(override.script)} for ${override.covers}`, true);
  }
  return rows;
}

/** When a settlement's transaction can be broadcast. */
export function broadcastText(broadcast) {
  switch (broadcast.when) {
    case 'now':
      return 'Now: as soon as the funding transaction confirms.';
    case 'after-height':
      return `Once the chain passes block ${broadcast.height.toLocaleString('en-US')}.`;
    case 'after-time':
      return broadcast.reached
        ? `Now: ${broadcast.utc} has passed by this browser's clock. Nodes accept it once the chain's median time, about an hour behind, passes it too.`
        : `Not before ${broadcast.utc}: until the chain's median time passes it, nodes reject the transaction.`;
    default:
      return '';
  }
}

/** How many CET rows to show before asking. Numeric contracts can have thousands. */
export const CET_PAGE = 100;
