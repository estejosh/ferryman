// Generates tests/data/hive_vectors.json with the reference implementation, so the
// Rust transaction code is checked byte for byte against something it did not write.
//
//   cd crates/ferryman-hive-rescue/tests/data
//   npm install --no-save @hiveio/dhive@1.3.2
//   node gen_vectors.mjs > hive_vectors.json
//
// (or `DHIVE_DIR=/path/with/node_modules node gen_vectors.mjs`). Output is
// deterministic: keys come from `PrivateKey.fromSeed(seed)`, everything else is fixed
// below, so a rerun with dhive 1.3.2 must reproduce the committed file exactly. The
// keys are throwaway test keys and guard nothing.
//
// Each vector holds the inputs (`wif`, `account`, `required_auths`, `id`, `json`, the
// reference block and expiration), and what dhive made of them: `serialized_hex`
// (`Types.Transaction`), `digest_hex` (`cryptoUtils.transactionDigest`, mainnet chain
// id) and `signature` (`PrivateKey.sign`). `attempts` is how many tries dhive's
// signing loop needed before it found a canonical signature (the nonce data is
// sha256(digest || attempt)); a vector with attempts > 1 exercises the retry path.

import { createRequire } from 'node:module';

const require = createRequire(
  process.env.DHIVE_DIR ? `${process.env.DHIVE_DIR}/` : import.meta.url,
);
const dhive = require('@hiveio/dhive');
const secp256k1 = require('secp256k1');
const { PrivateKey, cryptoUtils, Types } = dhive;
const ByteBuffer = require('@ecency/bytebuffer');

if (dhive.VERSION !== '1.3.2') {
  console.error(`expected @hiveio/dhive 1.3.2, found ${dhive.VERSION}`);
  process.exit(1);
}

const ID = 'ferryman-rescue-v1';

function attemptsFor(key, digest) {
  let attempts = 0;
  for (;;) {
    const data = cryptoUtils.sha256(Buffer.concat([digest, Buffer.alloc(1, ++attempts)]));
    const { signature } = secp256k1.sign(digest, key.key, { data });
    if (cryptoUtils.isCanonicalSignature(signature)) return attempts;
  }
}

function vector(seed, spec, n) {
  const key = PrivateKey.fromSeed(seed);
  const tx = {
    ref_block_num: 34293 + n,
    ref_block_prefix: 3293637341 + n,
    expiration: new Date(Date.UTC(2026, 9, 21, 22, 0, 10 + n)).toISOString().slice(0, 19),
    operations: [
      [
        'custom_json',
        {
          required_auths: spec.required_auths ?? [],
          required_posting_auths: [spec.account],
          id: spec.id ?? ID,
          json: spec.json,
        },
      ],
    ],
    extensions: [],
  };
  const buffer = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
  Types.Transaction(buffer, tx);
  buffer.flip();
  const serialized = Buffer.from(buffer.toBuffer());
  const digest = cryptoUtils.transactionDigest(tx);
  const signature = key.sign(digest).toString();
  const out = {
    seed,
    wif: key.toString(),
    pub: key.createPublic().toString(),
    account: spec.account,
    json: spec.json,
    ref_block_num: tx.ref_block_num,
    ref_block_prefix: tx.ref_block_prefix,
    expiration: tx.expiration,
    serialized_hex: serialized.toString('hex'),
    digest_hex: digest.toString('hex'),
    signature,
    attempts: attemptsFor(key, digest),
  };
  if (spec.required_auths) out.required_auths = spec.required_auths;
  if (spec.id) out.id = spec.id;
  return out;
}

const specs = [
  ['rescue-test-1', { account: 'ferryfleet', json: '{"v":1,"f":"x","e":"AAAA"}' }],
  ['rescue-test-2', { account: 'fleet.account', json: '{"hello":"wörld \\"q\\""}' }],
  ['rescue-test-3', { account: 'a', json: 'x'.repeat(300) }],
  // json longer than 16383 would need a 3-byte length; the cap is 8191, so 2 bytes is the top
  ['rescue-edge-longest', { account: 'ferryfleet', json: 'y'.repeat(8191) }],
  ['rescue-edge-127', { account: 'ferryfleet', json: 'z'.repeat(127) }],
  ['rescue-edge-128', { account: 'ferryfleet', json: 'z'.repeat(128) }],
  ['rescue-edge-unicode', { account: 'fleet-ops', json: '{"k":"日本語 ✓ ñ 🦀"}' }],
  ['rescue-edge-empty', { account: 'ferryfleet', json: '' }],
  ['rescue-edge-account-16', { account: 'sixteen-chars-ok', json: '{}' }],
  [
    'rescue-edge-both-auths',
    { account: 'ferryfleet', required_auths: ['alice', 'bob.smith'], json: '[]' },
  ],
  ['rescue-edge-other-id', { account: 'ferryfleet', id: 'a', json: '{}' }],
];

// Seeds whose first signing attempt is not canonical, so dhive retries: the first seed
// found for each of 2, 3 and 4+ attempts (deterministic, searched in order).
const wanted = new Set([2, 3, 4]);
const RETRY_N = 50; // the vectors' reference block and expiry are part of what is signed
const probe = { account: 'ferryfleet', json: '{"v":1,"retry":true}' };
for (let i = 0; wanted.size > 0 && i < 5000; i += 1) {
  const seed = `rescue-retry-${i}`;
  const got = vector(seed, probe, RETRY_N).attempts;
  const bucket = Math.min(got, 4);
  if (wanted.has(bucket)) {
    wanted.delete(bucket);
    specs.push([seed, { ...probe, n: RETRY_N }]);
  }
}
if (wanted.size > 0) {
  console.error('could not find seeds for every retry count');
  process.exit(1);
}

const vectors = specs.map(([seed, spec], i) => vector(seed, spec, spec.n ?? i));
process.stdout.write(`${JSON.stringify(vectors, null, 1)}\n`);
