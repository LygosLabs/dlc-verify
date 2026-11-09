// The page: reads the form, calls the WebAssembly module (engine.js) and shows what it answers.
// Everything a message says (outcomes, ids, addresses) is written as text, never as HTML.

import { call, ready, version } from './engine.js';
import {
  attestationsRequest,
  broadcastText,
  bundleHasAttestations,
  CET_PAGE,
  contractRows,
  locktimeText,
  messagesRequest,
  outputText,
  policyRequest,
  sats,
  scriptText,
  verdict,
} from './view.js';

const $ = (id) => document.getElementById(id);

/** Creates an element; strings among `children` become text nodes. */
function h(tag, attributes = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === 'class') element.className = value;
    else element.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child !== undefined && child !== null && child !== false) element.append(child);
  }
  return element;
}

const MAX_FILE = 32 * 1024 * 1024;

const state = {
  mode: 'bundle',
  // The messages part of the last verified request, reused to settle and refund.
  messages: null,
  report: null,
  cetsShown: 0,
  settlement: null,
};

// Loading

async function start() {
  try {
    await ready();
    $('version').textContent = `dlc-verify ${await version()}`;
    const response = await call('profiles');
    if (response.ok) {
      for (const profile of response.profiles) {
        $('profile').append(h('option', { value: profile.name }, profile.name));
      }
      showProfileAbout(response.profiles);
    }
    $('verify').disabled = false;
    formStatus('');
  } catch (error) {
    formStatus(`Could not load the verifier: ${error.message}`, true);
  }
}

function showProfileAbout(profiles) {
  const about = () => {
    const chosen = profiles.find((profile) => profile.name === $('profile').value);
    $('profile-about').textContent = chosen ? chosen.about : '';
  };
  $('profile').addEventListener('change', about);
  about();
}

// The form

function selectTab(mode) {
  state.mode = mode;
  for (const [name, tab, panel] of [
    ['bundle', $('tab-bundle'), $('panel-bundle')],
    ['separate', $('tab-separate'), $('panel-separate')],
  ]) {
    const selected = name === mode;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    panel.hidden = !selected;
  }
  markStale();
}

function wireTabs() {
  const tabs = [$('tab-bundle'), $('tab-separate')];
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectTab(index === 0 ? 'bundle' : 'separate'));
    tab.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      const next = tabs[(index + 1) % tabs.length];
      next.focus();
      next.click();
    });
  });
}

function policyMode() {
  return document.querySelector('input[name="policy-mode"]:checked')?.value ?? 'none';
}

function wirePolicy() {
  const update = () => {
    const mode = policyMode();
    $('profile-fields').hidden = mode !== 'profile';
    $('policy-fields').hidden = mode !== 'policy';
  };
  for (const radio of document.querySelectorAll('input[name="policy-mode"]')) {
    radio.addEventListener('change', update);
  }
  update();
}

async function readFile(file, target) {
  if (!file) return;
  if (file.size > MAX_FILE) {
    formStatus(`${file.name} is ${Math.round(file.size / 1e6)} MB; that is too big to be DLC messages.`, true);
    return;
  }
  target.value = await file.text();
  target.dispatchEvent(new Event('input', { bubbles: true }));
  formStatus('');
}

function wireFiles() {
  for (const [input, target] of [
    [$('bundle-file'), $('bundle')],
    [$('terms-file'), $('terms')],
    [$('policy-file'), $('policy')],
  ]) {
    input.addEventListener('change', async () => {
      await readFile(input.files?.[0], target);
      input.value = '';
    });
  }
  const box = $('bundle');
  box.addEventListener('dragover', (event) => {
    if (!event.dataTransfer?.types.includes('Files')) return;
    event.preventDefault();
    box.classList.add('dragging');
  });
  box.addEventListener('dragleave', () => box.classList.remove('dragging'));
  box.addEventListener('drop', (event) => {
    box.classList.remove('dragging');
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    event.preventDefault();
    readFile(file, box);
  });
}

function clockNow() {
  return $('use-clock').checked ? Math.floor(Date.now() / 1000) : undefined;
}

function utc(unix) {
  return new Date(unix * 1000).toISOString().replace('.000Z', 'Z');
}

function tickClock() {
  const now = clockNow();
  $('clock-now').textContent = now === undefined ? 'no clock: maturity checks only warn' : utc(now);
}

function formStatus(text, error = false) {
  $('form-status').textContent = text;
  $('form-status').classList.toggle('error', error);
}

function closeStatus(text, error = false) {
  $('close-status').textContent = text;
  $('close-status').classList.toggle('error', error);
}

/** Lets the page paint (a busy label, say) before a call that blocks the main thread. */
function paint() {
  return new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 0)));
}

function fields() {
  return {
    bundle: $('bundle').value,
    offer: $('offer').value,
    accept: $('accept').value,
    sign: $('sign').value,
    profile: $('profile').value,
    terms: $('terms').value,
    policy: $('policy').value,
  };
}

function markStale() {
  if (!state.report) return;
  $('stale').hidden = false;
  $('settle').disabled = true;
  $('refund').disabled = true;
}

// Verify

async function onVerify() {
  let messages;
  let policy;
  try {
    messages = messagesRequest(state.mode, fields());
    policy = policyRequest(policyMode(), fields());
  } catch (error) {
    formStatus(error.message, true);
    return;
  }
  const now = clockNow();
  const button = $('verify');
  button.disabled = true;
  button.textContent = 'Verifying…';
  formStatus('');
  await paint();
  try {
    const response = await call('verify', { ...messages, ...policy, now });
    if (!response.ok) {
      formStatus(errorText(response.error), true);
      return;
    }
    state.messages = messages;
    showReport(response, now);
    $('verdict').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    formStatus(`Could not verify: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = 'Verify';
  }
}

function errorText(error) {
  const lead = {
    request: 'The page sent a request the verifier refused',
    input: 'The messages could not be read',
    policy: 'The terms could not be read',
    attestation: 'The attestation could not be used',
    incomplete: 'Not enough messages',
    'no-cet': 'The attestation settles no CET',
    signature: 'A signature does not verify',
    internal: 'Something went wrong',
  }[error.kind];
  return lead ? `${lead}: ${error.message}` : error.message;
}

function showReport(response, now) {
  const { report } = response;
  state.report = report;
  state.settlement = null;
  $('result').hidden = false;
  $('stale').hidden = true;

  const { title, detail } = verdict(report);
  $('verdict').className = `verdict ${report.status}`;
  $('verdict-title').textContent = title;
  $('verdict-detail').textContent = detail;
  $('verdict-clock').textContent =
    now === undefined
      ? 'No clock was given, so the maturity checks only warn.'
      : `Checked against this browser's clock: ${utc(now)}.`;

  showContract(report.contract);
  showChecks();
  showPolicy(report.policy, response.notes ?? []);
  showPayouts(report.payouts);
  $('report-text').textContent = response.text;
  showClose(report);
}

function showContract(contract) {
  $('contract-card').hidden = !contract;
  $('contract').replaceChildren(
    ...contractRows(contract).flatMap((row) => [
      h('dt', {}, row.label),
      h('dd', { class: row.mono ? 'mono' : null }, row.value),
    ]),
  );
}

function checkRows(checks) {
  return checks.map((check) =>
    h(
      'tr',
      {},
      h('td', {}, h('span', { class: `pill ${check.status}` }, check.status)),
      h('td', { class: 'id' }, check.id),
      h('td', {}, check.detail),
    ),
  );
}

function showChecks() {
  if (!state.report) return;
  const onlyProblems = $('only-problems').checked;
  const checks = state.report.checks.filter(
    (check) => !onlyProblems || check.status === 'warn' || check.status === 'fail',
  );
  $('checks').replaceChildren(...checkRows(checks));
  $('checks-empty').hidden = checks.length > 0;
}

function showPolicy(policy, notes) {
  $('policy-card').hidden = !policy;
  if (!policy) return;
  $('policy-title').replaceChildren(
    'Expected terms',
    policy.name ? h('span', { class: 'hint' }, ` ${policy.name}`) : null,
    ' ',
    h('span', { class: `pill ${policy.status}` }, policy.status),
  );
  $('policy-notes').replaceChildren(...notes.map((note) => h('li', {}, note)));
  $('policy-checks').replaceChildren(...checkRows(policy.checks));
}

function outputsList(outputs) {
  return h(
    'ul',
    { class: 'outputs' },
    outputs.length ? outputs.map((output) => h('li', {}, outputText(output))) : h('li', {}, 'nothing'),
  );
}

function showPayouts(payouts) {
  $('payouts-card').hidden = !payouts;
  if (!payouts) return;
  $('refund-from').textContent = `from ${locktimeText(payouts.refund.locktime)}`;
  $('refund-outputs').replaceChildren(...outputsList(payouts.refund.outputs).children);
  $('cet-count').textContent = `(${payouts.cets.length.toLocaleString('en-US')})`;
  state.cetsShown = 0;
  $('cets').replaceChildren();
  showMoreCets();
}

function showMoreCets() {
  const cets = state.report?.payouts?.cets ?? [];
  const next = cets.slice(state.cetsShown, state.cetsShown + CET_PAGE);
  $('cets').append(
    ...next.map((cet) =>
      h(
        'tr',
        {},
        h('td', { class: 'id' }, String(cet.index)),
        h('td', { class: 'outcome' }, cet.outcome),
        h('td', {}, outputsList(cet.outputs)),
      ),
    ),
  );
  state.cetsShown += next.length;
  const left = cets.length - state.cetsShown;
  $('more-cets').hidden = left <= 0;
  $('more-cets').textContent = `Show ${Math.min(left, CET_PAGE)} more of ${left.toLocaleString('en-US')}`;
}

// Settle and refund

function showClose(report) {
  const usable = Boolean(report.contract);
  $('close-card').hidden = !usable;
  $('settlement').hidden = true;
  closeStatus('');
  $('settle').disabled = false;
  $('refund').disabled = false;
  const bundle = state.messages?.input;
  $('attestations-hint').textContent =
    bundle && bundleHasAttestations(bundle)
      ? 'Leave this empty to use the attestations in the bundle.'
      : 'Paste the attestation the oracle published for this contract’s event.';
  const refund = report.contract?.refund_locktime;
  $('refund-when').textContent = refund
    ? `Valid from ${locktimeText(refund)}. Before that, nodes reject it.`
    : '';
}

async function onSettle(kind) {
  if (!state.messages) return;
  let request = { ...state.messages, now: clockNow() };
  if (kind === 'settle') {
    const attestations = attestationsRequest($('attestations').value);
    const bundle = state.messages.input;
    if (!attestations.attestations && !(bundle && bundleHasAttestations(bundle))) {
      closeStatus('Paste the oracle’s attestation first.', true);
      return;
    }
    request = { ...request, ...attestations };
  }
  const button = $(kind);
  button.disabled = true;
  closeStatus(kind === 'settle' ? 'Building the CET…' : 'Building the refund…');
  await paint();
  try {
    const response = await call(kind, request);
    if (!response.ok) {
      $('settlement').hidden = true;
      closeStatus(errorText(response.error), true);
      return;
    }
    closeStatus('');
    showSettlement(response.settlement);
  } catch (error) {
    closeStatus(`Could not build the transaction: ${error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

function showSettlement(settlement) {
  state.settlement = settlement;
  $('settlement').hidden = false;
  $('settlement-title').textContent =
    settlement.kind === 'cet'
      ? `CET ${settlement.cet.index} for outcome ${settlement.cet.outcome}`
      : 'Refund';
  const warning = $('settlement-warning');
  warning.hidden = settlement.verification === 'pass';
  warning.textContent = `These messages did not pass verification (${settlement.verification}). The transaction is valid against the funding output they describe, but read the report before you broadcast it.`;

  const facts = [
    ['Txid', settlement.txid, true],
    [
      'Spends',
      `${settlement.spends.txid}:${settlement.spends.vout}, ${sats(settlement.spends.value_sat)}`,
      true,
    ],
  ];
  for (const attestation of settlement.cet?.attestations ?? []) {
    facts.push([
      'Attested',
      `oracle ${attestation.oracle_index} (${attestation.oracle_public_key}): event ${attestation.event_id}, outcome ${attestation.outcomes.join(' ')}`,
      true,
    ]);
  }
  for (const output of settlement.outputs) {
    facts.push(['Pays', `${sats(output.value_sat)} to ${output.payee} ${scriptText(output.script)}`]);
  }
  facts.push(['Fee', `${sats(settlement.fee_sat)}, ${settlement.vsize} vB`]);
  facts.push(['Broadcast', broadcastText(settlement.broadcast)]);
  $('settlement-facts').replaceChildren(
    ...facts.flatMap(([label, value, mono]) => [
      h('dt', {}, label),
      h('dd', { class: mono ? 'mono' : null }, value),
    ]),
  );
  $('settlement-tx').value = settlement.transaction;
  $('settlement').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Copy and download

async function copy(text, button) {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Copy failed: select and copy by hand';
  }
  setTimeout(() => {
    button.textContent = label;
  }, 1600);
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = h('a', { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function reportName() {
  const id = state.report?.contract?.contract_id ?? state.report?.contract?.temporary_contract_id;
  return `dlc-verify-${id ? id.slice(0, 16) : 'report'}.json`;
}

// Wiring

function wire() {
  wireTabs();
  wirePolicy();
  wireFiles();
  for (const input of document.querySelectorAll('[data-input]')) {
    input.addEventListener('input', markStale);
    input.addEventListener('change', markStale);
  }
  $('use-clock').addEventListener('change', tickClock);
  $('verify').addEventListener('click', onVerify);
  $('only-problems').addEventListener('change', showChecks);
  $('more-cets').addEventListener('click', showMoreCets);
  $('settle').addEventListener('click', () => onSettle('settle'));
  $('refund').addEventListener('click', () => onSettle('refund'));
  $('copy-report').addEventListener('click', (event) =>
    copy($('report-text').textContent, event.currentTarget),
  );
  $('download-report').addEventListener('click', () =>
    download(reportName(), `${JSON.stringify(state.report, null, 2)}\n`, 'application/json'),
  );
  $('copy-tx').addEventListener('click', (event) =>
    copy(state.settlement?.transaction ?? '', event.currentTarget),
  );
  $('download-tx').addEventListener('click', () => {
    if (!state.settlement) return;
    download(`${state.settlement.kind}-${state.settlement.txid}.hex`, `${state.settlement.transaction}\n`, 'text/plain');
  });
  // Ctrl/Cmd-Enter verifies from any box.
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || !(event.metaKey || event.ctrlKey)) return;
    if (event.target.closest?.('#close-card') || $('verify').disabled) return;
    onVerify();
  });
  tickClock();
  setInterval(tickClock, 1000);
}

wire();
start();
