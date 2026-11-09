// Checks the web page's scripts: the pure helpers in web/view.js, the module loader in
// web/engine.js against the built module and every fixture, and that every element app.js looks
// up exists in index.html.
//
//   node --test tools/web.test.mjs        (after tools/build-wasm.sh, which runs it)

import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const web = join(root, 'web');
const fixtures = join(root, 'fixtures');
const read = (path) => readFileSync(path, 'utf8');

// web/ is plain ES modules served as .js. Node reads .js by the nearest package.json, so the
// tests import a copy of web/ that has one saying so.
const scratch = mkdtempSync(join(tmpdir(), 'dlc-verify-web-'));
cpSync(web, scratch, { recursive: true });
writeFileSync(join(scratch, 'package.json'), '{"type": "module"}\n');
after(() => rmSync(scratch, { recursive: true, force: true }));

const view = await import(pathToFileURL(join(scratch, 'view.js')).href);

const bundles = readdirSync(fixtures)
  .filter((name) => name.endsWith('.json'))
  .sort()
  .map((name) => ({ name, text: read(join(fixtures, name)) }));

describe('view.js', () => {
  test('formats amounts, scripts and outputs', () => {
    assert.equal(view.sats(100000), '100,000 sat');
    const script = { hex: '0014ab', address: 'bc1qexample', kind: 'p2wpkh' };
    assert.equal(view.scriptText(script), 'bc1qexample');
    assert.equal(view.scriptText({ hex: '6a', kind: 'op-return' }), 'op-return script 6a');
    assert.equal(
      view.outputText({ payee: 'third-party', value_sat: 5000, script }),
      'third-party 5,000 sat to bc1qexample',
    );
    assert.equal(view.outputText({ payee: 'offerer', value_sat: 5000, script }), 'offerer 5,000 sat');
  });

  test('formats locktimes', () => {
    assert.equal(view.locktimeText({ value: 0, kind: 'none' }), '0 (no lock)');
    assert.equal(
      view.locktimeText({ value: 1768435200, kind: 'time', utc: '2026-01-15T00:00:00Z' }),
      '2026-01-15T00:00:00Z',
    );
    assert.equal(view.locktimeText({ value: 900000, kind: 'height' }), 'block 900,000');
  });

  test('builds the messages part of a request', () => {
    assert.deepEqual(view.messagesRequest('bundle', { bundle: ' {"offer": "a7"} ' }), {
      input: '{"offer": "a7"}',
    });
    assert.deepEqual(view.messagesRequest('bundle', { bundle: 'a71a\n00 11\n' }), {
      input: 'a71a0011',
    });
    assert.deepEqual(view.messagesRequest('separate', { offer: 'a7 1a', accept: '', sign: '' }), {
      offer: 'a71a',
    });
    assert.deepEqual(
      view.messagesRequest('separate', { offer: 'a71a', accept: 'a71c', sign: 'a71e' }),
      { offer: 'a71a', accept: 'a71c', sign: 'a71e' },
    );
    assert.throws(() => view.messagesRequest('bundle', { bundle: '  ' }), /Paste a bundle/);
    assert.throws(() => view.messagesRequest('separate', { offer: '' }), /Paste the offer/);
    assert.throws(
      () => view.messagesRequest('separate', { offer: 'a71a', sign: 'a71e' }),
      /needs the accept/,
    );
  });

  test('builds the policy part of a request', () => {
    assert.deepEqual(view.policyRequest('none', { policy: 'x' }), {});
    assert.deepEqual(view.policyRequest('profile', { profile: 'lygos-loan', terms: ' ' }), {
      profile: 'lygos-loan',
    });
    assert.deepEqual(view.policyRequest('profile', { profile: 'lygos-loan', terms: 'a = 1' }), {
      profile: 'lygos-loan',
      terms: 'a = 1',
    });
    assert.deepEqual(view.policyRequest('policy', { policy: 'name = "x"\n' }), {
      policy: 'name = "x"',
    });
    assert.throws(() => view.policyRequest('policy', { policy: '' }), /Paste a policy/);
    assert.throws(() => view.policyRequest('profile', { profile: '' }), /Choose a profile/);
  });

  test('builds the attestations part of a request', () => {
    assert.deepEqual(view.attestationsRequest(''), {});
    assert.deepEqual(view.attestationsRequest('fdd8 68\n01'), { attestations: 'fdd86801' });
    assert.deepEqual(view.attestationsRequest(' ["fdd868"] '), { attestations: '["fdd868"]' });
    assert.deepEqual(view.attestationsRequest('{"hex": "fdd868"}'), {
      attestations: '{"hex": "fdd868"}',
    });
  });

  test('knows which bundles carry attestations', () => {
    assert.equal(view.bundleHasAttestations('{"attestations": [{"hex": "fdd868"}]}'), true);
    assert.equal(view.bundleHasAttestations('{"attestations": []}'), false);
    assert.equal(view.bundleHasAttestations('{"offer": '), false);
    assert.equal(view.bundleHasAttestations('a71a'), false);
  });

  test('says when a transaction can be broadcast', () => {
    assert.match(view.broadcastText({ when: 'now' }), /^Now/);
    assert.match(view.broadcastText({ when: 'after-height', height: 900000 }), /900,000/);
    const time = { when: 'after-time', unix: 1, utc: '2026-01-15T00:00:00Z' };
    assert.match(view.broadcastText({ ...time, reached: false }), /^Not before 2026-01-15/);
    assert.match(view.broadcastText({ ...time, reached: true }), /^Now: 2026-01-15/);
  });

  test('says what a status means', () => {
    const counts = { pass: 3, warn: 1, fail: 0, skip: 2 };
    assert.equal(view.verdict({ status: 'pass', counts }).title, 'Pass');
    assert.match(view.verdict({ status: 'pass', counts }).detail, /3 passed, 1 warned, 2 not run/);
    assert.match(view.verdict({ status: 'pass', counts, policy: {} }).detail, /match the policy/);
    assert.equal(view.verdict({ status: 'fail', counts }).title, 'Fail');
    assert.equal(view.verdict({ status: 'incomplete', counts }).title, 'Incomplete');
  });

  test('lists the contract, ids and keys in monospace', () => {
    const report = JSON.parse(read(join(fixtures, 'reports', 'midnight-liquidator.json')));
    const rows = view.contractRows(report.contract);
    const row = (label) => rows.find((each) => each.label === label);
    assert.equal(row('Network').value, 'regtest');
    assert.equal(row('Contract id').mono, true);
    assert.equal(row('Collateral').value, '100,000 sat: offerer 100,000 sat, accepter 0 sat');
    assert.equal(row('Flags').value, 'refund-to-accepter');
    assert.equal(row('Refund locktime').value, '2026-01-15T00:00:00Z');
    assert.match(row('Third party').value, /^bcrt1q3qr7lswmh25nplahuj3m474ujs6vjvpu6976ja for /);
    assert.deepEqual(view.contractRows(null), []);
  });
});

describe('engine.js with the built module', () => {
  const built = (() => {
    try {
      readFileSync(join(web, 'pkg', 'dlc_verify_wasm_bg.wasm'));
      return true;
    } catch {
      return false;
    }
  })();
  let engine;

  before(async () => {
    if (!built) return;
    // engine.js fetches the module next to it; Node's fetch has no file: URLs.
    globalThis.fetch = async (url) =>
      new Response(readFileSync(fileURLToPath(url)), {
        headers: { 'content-type': 'application/wasm' },
      });
    engine = await import(pathToFileURL(join(scratch, 'engine.js')).href);
    await engine.ready();
  });

  test('loads the module and answers the version', { skip: !built && 'run tools/build-wasm.sh' }, async () => {
    assert.match(await engine.version(), /^\d+\.\d+\.\d+/);
    const { profiles } = await engine.call('profiles');
    assert.ok(profiles.length > 0);
  });

  test('every fixture verifies, renders and closes', { skip: !built && 'run tools/build-wasm.sh' }, async () => {
    for (const { name, text } of bundles) {
      const bundle = JSON.parse(text);
      const messages = view.messagesRequest('bundle', { bundle: text });
      const response = await engine.call('verify', { ...messages, now: bundle.now });
      assert.equal(response.ok, true, name);
      const { report } = response;
      assert.equal(report.status, 'pass', name);
      assert.ok(view.contractRows(report.contract).length >= 10, name);
      assert.ok(view.verdict(report).title, name);
      for (const cet of report.payouts.cets) {
        for (const output of cet.outputs) assert.match(view.outputText(output), /\d sat/, name);
      }

      const refund = await engine.call('refund', { ...messages, now: bundle.now });
      assert.equal(refund.ok, true, name);
      assert.ok(view.broadcastText(refund.settlement.broadcast), name);

      if (view.bundleHasAttestations(text)) {
        const settled = await engine.call('settle', { ...messages, now: bundle.now });
        assert.equal(settled.ok, true, `${name}: ${JSON.stringify(settled.error)}`);
        assert.equal(settled.settlement.kind, 'cet', name);
      }
    }
  });

  test('separate messages and pasted attestations work too', { skip: !built && 'run tools/build-wasm.sh' }, async () => {
    const bundle = JSON.parse(read(join(fixtures, 'enum-payout-override.json')));
    const messages = view.messagesRequest('separate', bundle);
    const verified = await engine.call('verify', { ...messages });
    assert.equal(verified.report.status, 'pass');
    const attestation = view.attestationsRequest(bundle.attestations[0].hex);
    const settled = await engine.call('settle', { ...messages, ...attestation });
    assert.equal(settled.ok, true, JSON.stringify(settled.error));
  });

  test('errors come back as responses', { skip: !built && 'run tools/build-wasm.sh' }, async () => {
    const response = await engine.call('verify', { input: 'zz' });
    assert.equal(response.ok, false);
    assert.equal(response.error.kind, 'input');
  });
});

describe('index.html', () => {
  const html = read(join(web, 'index.html'));
  const app = read(join(web, 'app.js'));

  test('has every element app.js looks up', () => {
    const ids = new Set([...html.matchAll(/\sid="([\w-]+)"/g)].map((match) => match[1]));
    const used = [...app.matchAll(/\$\('([\w-]+)'\)/g)].map((match) => match[1]);
    assert.ok(used.length > 30);
    for (const id of used) assert.ok(ids.has(id), `index.html has no #${id}`);
    const settleButtons = [...app.matchAll(/onSettle\('(\w+)'\)/g)].map((match) => match[1]);
    for (const id of settleButtons) assert.ok(ids.has(id), `index.html has no #${id}`);
  });

  test('loads nothing from other origins', () => {
    for (const match of html.matchAll(/<(?:script|link|img)\b[^>]*\b(?:src|href)="([^"]+)"/g)) {
      assert.doesNotMatch(match[1], /^(?:[a-z]+:)?\/\//i, `external resource ${match[1]}`);
    }
    assert.match(html, /Content-Security-Policy/);
    assert.match(html, /script-src 'self' 'wasm-unsafe-eval'/);
  });
});
