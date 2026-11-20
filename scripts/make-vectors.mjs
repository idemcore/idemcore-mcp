// Regenerates vectors/receipts-r2.json: r2 test receipts, a synthetic public log and an audit
// export, all signed with throwaway Ed25519 keys that are discarded when the script exits.
// Run after `npm run build`: node scripts/make-vectors.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { b64u, b64uDec, hex } from "../dist/bytes.js";
import { keyIdFor } from "../dist/keys.js";
import { promptHash, textHash, tokenHash, taggedHash, logDigests } from "../dist/hash.js";
import { signingPayload } from "../dist/receipt.js";
import { canonicalBytes } from "../dist/canonical.js";
import { eventHash, merkleRoot } from "../dist/audit.js";

const rnd = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
async function newKey() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const keyId = await keyIdFor(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  const sign = async (bytes) => b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, bytes)));
  return { keyId, jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: keyId }, sign };
}
const main = await newKey(), foreign = await newKey();

const messages = [{ role: "user", content: "What is the capital of France?" }];
const output_ids = [785, 6722, 315, 9625, 374, 12095, 13];
const output_text = "The capital of France is Paris.";
const salt = new Uint8Array([...Array(16).keys()]);
const prompt_tokens = 20;

// Synthetic public log (random values): L2 only recomputes chain_digest over these lines.
const lines = [];
for (let i = 0; i < prompt_tokens + output_ids.length; i++) lines.push(`${i} 0 ${rnd(8)} ${rnd(8)}`);
const placeholder = rnd(8);
const log_text = lines.join("\n") + `\nALL ${placeholder}\n`;
const badLines = [...lines];
const last = badLines[3].slice(-1);
badLines[3] = badLines[3].slice(0, -1) + (last === "0" ? "1" : "0");
const bad_log_text = badLines.join("\n") + `\nALL ${placeholder}\n`;
const { chain_digest } = await logDigests(log_text);

async function receipt(privacy, withText, key = main, id = "rcpt_" + rnd(12), issued = "2026-10-31T08:05:44.456Z") {
  const s = privacy === "full" ? new Uint8Array(0) : salt;
  const r = {
    receipt_version: "r2", receipt_id: id, issued_at: issued, tenant_id: "tnt_demo",
    model_id: "qwen2.5-7b-instruct-q4", weights_hash: "ab".repeat(32), engine_version: "0.2.0", engine_build: "demo",
    privacy, prompt_hash: await promptHash(messages, s),
    params_hash: await taggedHash("params", canonicalBytes({ max_tokens: 64 })), variant: 0, decoding: "greedy",
    prompt_tokens, output_tokens: output_ids.length, output_token_hash: await tokenHash(output_ids, s),
    chain_digest, chain_check: placeholder, log_ref: "log_demo_0001", finish_reason: "stop", key_id: key.keyId,
  };
  if (withText) r.output_text_hash = await textHash(output_text, s);
  r.signature = await key.sign(signingPayload(r));
  return r;
}
const full = await receipt("full", false);
const receipts = {
  full,
  hash_only: await receipt("hash_only", false),
  full_text: await receipt("full", true),
  hash_only_text: await receipt("hash_only", true),
  tampered: { ...full, model_id: "qwen2.5-72b-instruct" },
  foreign_key: await receipt("full", false, foreign),
};

const events = [];
let prev = "0".repeat(64);
const ids = [full.receipt_id, receipts.hash_only.receipt_id, full.receipt_id];
const types = ["receipt.issued", "receipt.issued", "receipt.viewed"];
for (let i = 0; i < 3; i++) {
  const ev = { tenant_id: "tnt_demo", seq: i + 1, ts: `2026-10-31T07:0${i + 1}:00.000Z`, event_type: types[i],
    receipt_id: ids[i], actor: "api", payload: { n: i + 1 }, prev_hash: prev };
  ev.event_hash = await eventHash(ev); prev = ev.event_hash; events.push(ev);
}
const root = { tenant_id: "tnt_demo", day: "2026-10-31", count: 3, first_seq: 1, last_seq: 3,
  merkle_root: await merkleRoot(events.map((e) => e.event_hash)), key_id: main.keyId };
const rootDomain = new TextEncoder().encode("idemcore-audit-root/r1\n");
const body = canonicalBytes(root);
const msg = new Uint8Array(rootDomain.length + body.length); msg.set(rootDomain); msg.set(body, rootDomain.length);
root.signature = await main.sign(msg);

const out = {
  _note: "Test vectors only. Throwaway signing keys, discarded after generation. The log values and chain_check are synthetic; L2 recomputes chain_digest from the log lines.",
  keys: [main.jwk], messages, output_ids, output_text, salt_b64u: b64u(salt), log_text, bad_log_text, receipts,
  audit: { events, roots: [root], receipts: [full, receipts.hash_only] },
  expect: { full: { l1: true, l2: true }, hash_only: { l1: true }, tampered: { l1: false }, foreign_key: { l1: false }, bad_log: { l2: false } },
};
writeFileSync(new URL("../vectors/receipts-r2.json", import.meta.url), JSON.stringify(out, null, 1) + "\n");
console.log("wrote vectors/receipts-r2.json");
