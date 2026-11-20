import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { importKeySet } from "../src/keys.js";
import { verifyDisclosure, verifyL1, verifyL2 } from "../src/receipt.js";
import { verifyEventChain, verifyRoot, merkleRoot } from "../src/audit.js";
import { b64uDec } from "../src/bytes.js";

const V = JSON.parse(readFileSync(new URL("../vectors/receipts-r2.json", import.meta.url), "utf8"));
const keys = await importKeySet(V.keys, "vectors");
const R = V.receipts;
const salt = b64uDec(V.salt_b64u);

describe("receipt test vectors", () => {
  it("L1 accepts every genuine receipt", async () => {
    for (const k of ["full", "hash_only", "full_text", "hash_only_text"]) expect((await verifyL1(R[k], keys)).ok, k).toBe(true);
  });
  it("L1 rejects a tampered field", async () => {
    const r = await verifyL1(R.tampered, keys);
    expect(r.ok).toBe(false); expect(r.errors).toContain("signature does not verify");
  });
  it("L1 rejects a receipt signed by an untrusted key", async () => {
    const r = await verifyL1(R.foreign_key, keys);
    expect(r.ok).toBe(false); expect(r.errors[0]).toMatch(/unknown key_id/);
  });
  it("L1 rejects unknown fields and bad formats", async () => {
    expect((await verifyL1({ ...R.full, extra: "x" }, keys)).errors).toContain("unknown field extra");
    expect((await verifyL1({ ...R.full, extra: 1 }, keys)).errors).toContain("unknown field extra");
    expect((await verifyL1({ ...R.full, variant: 1.5 }, keys)).ok).toBe(false);
    expect((await verifyL1("nope", keys)).ok).toBe(false);
  });
  it("L2 matches the log and catches a one-character change", async () => {
    expect((await verifyL2(R.full, V.log_text)).ok).toBe(true);
    const bad = await verifyL2(R.full, V.bad_log_text);
    expect(bad.ok).toBe(false); expect(bad.errors.join()).toMatch(/chain_digest mismatch/);
  });
  it("disclosure: prompt, token ids and displayed text (full)", async () => {
    const r = await verifyDisclosure(R.full_text, { messages: V.messages, outputIds: V.output_ids, outputText: V.output_text });
    expect(r.ok).toBe(true); expect(r.checked).toEqual(["prompt_hash", "output_token_hash", "output_text_hash"]);
    expect((await verifyDisclosure(R.full_text, { outputText: V.output_text + " (edited)" })).ok).toBe(false);
  });
  it("disclosure: hash_only needs the right salt", async () => {
    expect((await verifyDisclosure(R.hash_only_text, { messages: V.messages, outputText: V.output_text, salt })).ok).toBe(true);
    expect((await verifyDisclosure(R.hash_only_text, { outputText: V.output_text })).errors[0]).toMatch(/salt required/);
    expect((await verifyDisclosure(R.hash_only_text, { outputText: V.output_text, salt: new Uint8Array(16) })).ok).toBe(false);
  });
  it("receipts without output_text_hash cannot bind displayed text", async () => {
    const r = await verifyDisclosure(R.full, { outputText: V.output_text });
    expect(r.ok).toBe(false); expect(r.errors[0]).toMatch(/no output_text_hash/);
  });
});

describe("audit vectors", () => {
  it("event chain and signed Merkle root verify", async () => {
    expect(await verifyEventChain(V.audit.events)).toEqual([]);
    expect(await verifyRoot(V.audit.roots[0], V.audit.events, keys)).toEqual([]);
  });
  it("editing or dropping an event breaks the chain and the root", async () => {
    const evs = structuredClone(V.audit.events); evs[1].payload = { n: 99 };
    expect((await verifyEventChain(evs)).join()).toMatch(/event_hash mismatch at seq 2/);
    const dropped = V.audit.events.slice(0, 2);
    expect(await verifyRoot(V.audit.roots[0], dropped, keys)).toContain("merkle_root mismatch");
  });
  it("merkle root of empty set", async () => {
    expect(await merkleRoot([])).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("display-text normalisation", () => {
  it("ignores whitespace layout and Unicode composition, not wording", async () => {
    const { verifyDisclosure: vd } = await import("../src/receipt.js");
    const variants = ["  The capital of\nFrance  is\u00a0Paris. ", "The capital of France is Paris.\r\n"];
    for (const t of variants) expect((await vd(R.full_text, { outputText: t })).ok, JSON.stringify(t)).toBe(true);
    expect((await vd(R.full_text, { outputText: "The capital of France is Lyon." })).ok).toBe(false);
    const { normalizeText } = await import("../src/hash.js");
    expect(normalizeText("Cafe\u0301")).toBe("Café");
  });
});

describe("public token log + bundled keys", () => {
  it("test vector log lines use the pi j h hc format and lines with extra fields are rejected", async () => {
    const { parseLog } = await import("../src/hash.js");
    for (const l of V.log_text.trim().split("\n")) expect([2, 4]).toContain(l.split(" ").length);
    const withExtra = V.log_text.replace(/^(\d+ \d+ [0-9a-f]+ [0-9a-f]+)$/m, "$1 1 2");
    expect(() => parseLog(withExtra)).toThrow(/not a public log line/);
  });
  it("bundled production key is well-formed", async () => {
    const { DEFAULT_TRUSTED_KEYS } = await import("../src/default-keys.js");
    const ks = await importKeySet(DEFAULT_TRUSTED_KEYS, "bundled");
    expect(ks.map((k) => k.keyId)).toContain("ed25519:2fab59995ac55e4f");
    for (const k of DEFAULT_TRUSTED_KEYS) expect(Object.keys(k).sort()).toEqual(["crv", "kid", "kty", "x"]);
  });
  it("KeyStore includes the bundled key unless disabled", async () => {
    const { KeyStore } = await import("../src/config.js");
    const base = { baseUrl: "http://127.0.0.1:9", exportDir: ".", timeoutMs: 1000, fetchImpl: fetch };
    expect((await new KeyStore(base).get()).keys.map((k) => k.keyId)).toEqual(["ed25519:2fab59995ac55e4f"]);
    expect((await new KeyStore({ ...base, defaultKeys: false }).get()).keys).toEqual([]);
  });
});
