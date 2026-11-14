#!/usr/bin/env node
// Skrivni Miklavž — one-time draw + site build.
//
//   node organizer/draw.mjs --base-url https://<user>.github.io/<repo>/
//
// Writes:
//   docs/data.js        encrypted assignments (safe to publish)
//   organizer/links.txt name → link list (PRIVATE — send each link to its owner, never publish)
//
// The draw is never printed or stored in plain text. Each assignment is encrypted
// with AES-GCM under a key derived from that person's random token, so only the
// matching link can decrypt it.

import { webcrypto, randomInt, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const subtle = webcrypto.subtle;

// ---- Configuration ---------------------------------------------------------

const PARTICIPANTS = [
  'Matija', 'Lenka', 'Anja', 'Miha', 'Klara', 'Damjan', 'Mojca', 'Borut',
  'Nevenka', 'Stanko', 'Petra', 'Marica', 'Franc', 'Veronika', 'Grega', 'Lenart',
];

// Pairs that may not draw each other (in either direction), e.g. [['Miha', 'Klara']].
const EXCLUSIONS = [];

// Must match SALT in docs/app.js.
const SALT = 'skrivni-miklavz-2026';
// Plaintext is padded to this many bytes so ciphertext length reveals nothing about names.
const PAD_BYTES = 96;

// ---- Paths & arguments -----------------------------------------------------

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataFile = path.join(root, 'docs', 'data.js');
const linksFile = path.join(root, 'organizer', 'links.txt');

const args = process.argv.slice(2);
const force = args.includes('--force');
const baseIdx = args.indexOf('--base-url');
let baseUrl = baseIdx >= 0 ? args[baseIdx + 1] : undefined;

function fail(msg) {
  console.error(`\n✖ ${msg}\n`);
  process.exit(1);
}

if (!baseUrl) {
  fail('Missing --base-url.\n  Example: node organizer/draw.mjs --base-url https://<user>.github.io/<repo>/');
}
try {
  const u = new URL(baseUrl);
  if (!/^https?:$/.test(u.protocol)) throw new Error();
  u.search = '';
  u.hash = '';
  if (!u.pathname.endsWith('/')) u.pathname += '/';
  baseUrl = u.toString();
} catch {
  fail(`Invalid --base-url: ${baseUrl}`);
}

if (!force && (fs.existsSync(dataFile) || fs.existsSync(linksFile))) {
  fail(
    'The draw has already been made (docs/data.js or organizer/links.txt exists).\n' +
    '  It is generated only once. To deliberately redo it and invalidate ALL old links,\n' +
    '  re-run with --force.'
  );
}

// ---- Sanity checks ---------------------------------------------------------

if (new Set(PARTICIPANTS).size !== PARTICIPANTS.length) fail('Duplicate participant names.');
if (PARTICIPANTS.length < 3) fail('Need at least 3 participants.');
for (const [a, b] of EXCLUSIONS) {
  if (!PARTICIPANTS.includes(a) || !PARTICIPANTS.includes(b)) fail(`Unknown name in exclusion [${a}, ${b}].`);
}
const excluded = (a, b) => EXCLUSIONS.some(([x, y]) => (x === a && y === b) || (x === b && y === a));

// ---- Draw: one single loop A→B→C→…→A ---------------------------------------

function shuffle(list) {
  const a = [...list];
  for (let i = a.length - 1; i > 0; i--) {
    const j = randomInt(i + 1); // cryptographically secure
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function drawCycle() {
  for (let attempt = 0; attempt < 100000; attempt++) {
    const order = shuffle(PARTICIPANTS);
    const ok = order.every((g, i) => !excluded(g, order[(i + 1) % order.length]));
    if (ok) return order;
  }
  fail('Could not find a valid loop with these exclusions.');
}

const order = drawCycle();
const assignment = new Map(order.map((g, i) => [g, order[(i + 1) % order.length]]));

// Verify invariants before writing anything.
{
  const receivers = new Set(assignment.values());
  if (receivers.size !== PARTICIPANTS.length) fail('Internal error: not a permutation.');
  for (const [g, r] of assignment) if (g === r) fail('Internal error: self-assignment.');
  let cur = PARTICIPANTS[0], steps = 0;
  do { cur = assignment.get(cur); steps++; } while (cur !== PARTICIPANTS[0]);
  if (steps !== PARTICIPANTS.length) fail('Internal error: not a single loop.');
}

// ---- Crypto (must mirror docs/app.js) -------------------------------------

const enc = (s) => new TextEncoder().encode(s);
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const b64 = (buf) => Buffer.from(buf).toString('base64');
const hex = (buf) => Buffer.from(buf).toString('hex');

async function deriveFromToken(tokenBytes) {
  const ikm = await subtle.importKey('raw', tokenBytes, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const salt = enc(SALT);
  const id = hex(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc('id') }, ikm, 256));
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc('aes-gcm-key') },
    ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  return { id, key };
}

function padded(obj) {
  const bytes = enc(JSON.stringify(obj));
  if (bytes.length > PAD_BYTES) fail('Names too long for PAD_BYTES; increase it.');
  const out = new Uint8Array(PAD_BYTES).fill(0x20); // spaces — JSON.parse ignores trailing whitespace
  out.set(bytes);
  return out;
}

const entries = [];
const links = [];
for (const giver of PARTICIPANTS) {
  const tokenBytes = randomBytes(32); // 256-bit token
  const token = b64url(tokenBytes);
  const { id, key } = await deriveFromToken(tokenBytes);
  const iv = randomBytes(12);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc(id) },
    key, padded({ g: giver, r: assignment.get(giver) })
  );
  entries.push([id, b64(Buffer.concat([iv, Buffer.from(ct)]))]);
  links.push([giver, `${baseUrl}?t=${token}`]);
}

// Order entries by their (random) id so file order reveals nothing.
entries.sort((a, b) => (a[0] < b[0] ? -1 : 1));

// ---- Write output ----------------------------------------------------------

const js =
  '// Generated by organizer/draw.mjs — encrypted, safe to publish. Do not edit.\n' +
  `window.MIKLAVZ_DATA = ${JSON.stringify({ v: 1, entries: Object.fromEntries(entries) }, null, 1)};\n`;
fs.writeFileSync(dataFile, js);

const width = Math.max(...PARTICIPANTS.map((n) => n.length));
const list = links.map(([n, l]) => `${n.padEnd(width)}  →  ${l}`).join('\n');
fs.writeFileSync(
  linksFile,
  `Skrivni Miklavž — private links (send each person ONLY their own link)\n` +
  `Generated ${new Date().toISOString()}\n\n${list}\n`
);

console.log(`\n✔ Draw done: ${PARTICIPANTS.length} people, one single loop, nobody draws themselves.`);
console.log(`✔ Wrote docs/data.js (encrypted) and organizer/links.txt (private).\n`);
console.log(list + '\n');
console.log('Next: publish the docs/ folder. Never publish organizer/links.txt.\n');
