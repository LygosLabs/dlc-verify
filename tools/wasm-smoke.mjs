// Loads the built module as a browser does (the `--target web` glue, initialised from bytes) and
// checks it against every fixture: the reports must match the snapshots byte for byte, and every
// attested CET and every refund must settle.
//
//   node tools/wasm-smoke.mjs [web/pkg]

import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = resolve(process.argv[2] ?? join(root, 'web/pkg'));
const fixtures = join(root, 'fixtures');
const read = (path) => readFileSync(path, 'utf8');

// The glue is an ES module with a .js name and no package.json beside it; Node needs .mjs.
const scratch = mkdtempSync(join(tmpdir(), 'dlc-verify-wasm-'));
let dlc;
try {
  copyFileSync(join(pkg, 'dlc_verify_wasm.js'), join(scratch, 'dlc_verify_wasm.mjs'));
  dlc = await import(pathToFileURL(join(scratch, 'dlc_verify_wasm.mjs')).href);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
dlc.initSync({ module: readFileSync(join(pkg, 'dlc_verify_wasm_bg.wasm')) });

const call = (fn, request) => JSON.parse(fn(JSON.stringify(request)));
const ok = (response, what) => {
  assert.equal(response.ok, true, `${what}: ${JSON.stringify(response.error)}`);
  return response;
};

const names = readdirSync(fixtures)
  .filter((name) => name.endsWith('.json'))
  .map((name) => name.slice(0, -'.json'.length))
  .sort();
assert.ok(names.length >= 9, 'expected the generated fixtures');

let settled = 0;
for (const name of names) {
  const bundle = JSON.parse(read(join(fixtures, `${name}.json`)));
  const { report, text } = ok(call(dlc.verify, { input: bundle, now: bundle.now }), name);
  assert.equal(text, read(join(fixtures, 'reports', `${name}.txt`)), `${name}: text report`);
  assert.deepEqual(
    report,
    JSON.parse(read(join(fixtures, 'reports', `${name}.json`))),
    `${name}: JSON report`,
  );

  if (bundle.attestations?.length) {
    const { settlement } = ok(call(dlc.settle, { input: bundle, now: bundle.now }), name);
    assert.equal(settlement.kind, 'cet', name);
    settled += 1;
  }
  const { settlement } = ok(call(dlc.refund, { input: bundle, now: bundle.now }), name);
  assert.equal(settlement.kind, 'refund', name);
}
assert.ok(settled >= 7, 'expected every attested fixture to settle');

const multi = JSON.parse(read(join(fixtures, 'enum-multi-oracle.json')));
const one = call(dlc.settle, { input: multi, attestations: [multi.attestations[0].hex] });
assert.equal(one.ok, false);
assert.equal(one.error.kind, 'no-cet');

const midnight = JSON.parse(read(join(fixtures, 'midnight-liquidator.json')));
const profiled = ok(
  call(dlc.verify, {
    input: JSON.stringify(midnight),
    now: midnight.now,
    profile: 'lygos-midnight',
    terms: read(join(fixtures, 'terms', 'midnight-liquidator.toml')),
  }),
  'profile',
);
assert.equal(profiled.report.policy.status, 'pass');

const bad = JSON.parse(dlc.verify('{"input": 5}'));
assert.deepEqual(bad.error.kind, 'request');
assert.equal(ok(JSON.parse(dlc.profiles()), 'profiles').profiles.length, 2);
assert.ok(ok(JSON.parse(dlc.oracles()), 'oracles').oracles.length > 0);
assert.match(dlc.version(), /^\d+\.\d+\.\d+/);

console.log(`wasm-smoke: ${names.length} fixtures verified, ${settled} settled, in ${pkg}`);
