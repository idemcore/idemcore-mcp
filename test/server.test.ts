import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createServer } from "../src/server.js";
import type { Config } from "../src/config.js";
import { API_KEY, startMock } from "./mock.js";

const V = JSON.parse(readFileSync(new URL("../vectors/receipts-r2.json", import.meta.url), "utf8"));

async function connect(cfg: Partial<Config> & { baseUrl: string }) {
  const full: Config = { apiKey: API_KEY, keysUrl: `${cfg.baseUrl}/v1/keys`, exportDir: mkdtempSync(join(tmpdir(), "icx-")),
    timeoutMs: 10000, fetchImpl: fetch, ...cfg };
  const [a, b] = InMemoryTransport.createLinkedPair();
  const server = createServer(full);
  await server.connect(a);
  const client = new Client({ name: "test", version: "0" });
  await client.connect(b);
  return { client, cfg: full };
}

const call = async (c: Client, name: string, args: Record<string, unknown> = {}) => {
  const r: any = await c.callTool({ name, arguments: args });
  const text: string = r.content[0].text;
  const json = JSON.parse(text.slice(text.indexOf("\n\n{") + 2));
  return { r, text, json };
};

describe("MCP server against a local mock API", () => {
  let mock: Awaited<ReturnType<typeof startMock>>;
  let c: Client;
  let exportDir: string;
  beforeAll(async () => { mock = await startMock({ withTextHash: true }); const x = await connect({ baseUrl: mock.url }); c = x.client; exportDir = x.cfg.exportDir; });
  afterAll(async () => { await mock.close(); });

  it("lists the tools", async () => {
    const names = (await c.listTools()).tools.map((t) => t.name).sort();
    expect(names).toEqual(["idemcore_chat", "idemcore_export_audit", "idemcore_get_receipt", "idemcore_trusted_keys", "idemcore_verify_audit", "idemcore_verify_receipt"]);
  });

  it("idemcore_chat returns the answer and a verified receipt (full)", async () => {
    const { text, json } = await call(c, "idemcore_chat", { prompt: "What is the capital of France?", privacy: "full", max_tokens: 64 });
    expect(json.answer).toBe("The capital of France is Paris.");
    expect(json.verification.verdict).toBe("VERIFIED");
    expect(json.verification.checks.map((x: any) => x.level)).toEqual(["L1", "disclosure"]);
    expect(json.verification.checks[1].checked).toEqual(["prompt_hash", "output_text_hash"]);
    expect(text).not.toContain(API_KEY);
    const req = mock.seen.find((s) => s.path === "/v1/chat/completions")!;
    expect(req.auth).toBe(`Bearer ${API_KEY}`);
    expect(req.body.idemcore).toEqual({ privacy: "full" });
  });

  it("idemcore_chat with hash_only uses the returned salt", async () => {
    const { json } = await call(c, "idemcore_chat", { prompt: "hi", privacy: "hash_only", seed: 7 });
    expect(json.receipt.privacy).toBe("hash_only");
    expect(json.receipt.variant).toBe(7);
    expect(json.verification.verdict).toBe("VERIFIED");
  });

  it("idemcore_get_receipt fetches and verifies a stored receipt", async () => {
    const id = [...mock.store.keys()][0];
    const { json } = await call(c, "idemcore_get_receipt", { receipt_id: id });
    expect(json.receipt.receipt_id).toBe(id);
    expect(json.verification.verdict).toBe("VERIFIED");
  });

  it("idemcore_export_audit saves a bundle and checks it", async () => {
    const { json } = await call(c, "idemcore_export_audit", { from: "2026-10-31", to: "2026-11-01" });
    expect(json.verdict).toBe("VERIFIED");
    expect(json.receipts_ok).toBe(json.receipts);
    expect(readdirSync(exportDir).length).toBe(1);
  });

  it("idemcore_verify_receipt works offline with the test vectors", async () => {
    const off = await connect({ baseUrl: "http://127.0.0.1:9", keysUrl: undefined, trustedKeysFile: writeKeys(V.keys) });
    const ok = await call(off.client, "idemcore_verify_receipt", { receipt: V.receipts.full_text, log_text: V.log_text, messages: V.messages, output_ids: V.output_ids, output_text: V.output_text });
    expect(ok.json.verdict).toBe("VERIFIED");
    expect(ok.json.checks.map((x: any) => x.level)).toEqual(["L1", "L2", "disclosure"]);
    const bad = await call(off.client, "idemcore_verify_receipt", { receipt: JSON.stringify(V.receipts.tampered) });
    expect(bad.json.verdict).toBe("FAILED"); expect(bad.r.isError).toBe(true);
    const badLog = await call(off.client, "idemcore_verify_receipt", { receipt: V.receipts.full, log_text: V.bad_log_text });
    expect(badLog.json.verdict).toBe("FAILED");
    const unknown = await call(off.client, "idemcore_verify_receipt", { receipt: V.receipts.foreign_key });
    expect(unknown.json.verdict).toBe("UNVERIFIED");
    const env = await call(off.client, "idemcore_verify_receipt", { receipt: { v: 1, receipt: V.receipts.hash_only_text }, output_text: V.output_text, salt_b64u: V.salt_b64u });
    expect(env.json.verdict).toBe("VERIFIED");
  });

  it("idemcore_verify_audit checks an exported bundle file", async () => {
    const off = await connect({ baseUrl: "http://127.0.0.1:9", keysUrl: undefined, trustedKeysFile: writeKeys(V.keys) });
    const p = join(mkdtempSync(join(tmpdir(), "ica-")), "bundle.json");
    writeFileSync(p, JSON.stringify(V.audit));
    expect((await call(off.client, "idemcore_verify_audit", { path: p })).json.verdict).toBe("VERIFIED");
    const t = structuredClone(V.audit); t.events[0].actor = "someone-else"; writeFileSync(p, JSON.stringify(t));
    const bad = await call(off.client, "idemcore_verify_audit", { path: p });
    expect(bad.json.verdict).toBe("FAILED");
  });

  it("a tampered receipt from the API is reported as FAILED", async () => {
    const m2 = await startMock({ tamper: true, receiptInHeader: true });
    const x = await connect({ baseUrl: m2.url });
    const { json } = await call(x.client, "idemcore_chat", { prompt: "hi" });
    expect(json.verification.verdict).toBe("FAILED");
    await m2.close();
  });

  it("errors never echo the API key", async () => {
    const x = await connect({ baseUrl: mock.url, apiKey: "wrong-" + API_KEY });
    const { r, text } = await call(x.client, "idemcore_chat", { prompt: "hi" });
    expect(r.isError).toBe(true); expect(text).toMatch(/401/); expect(text).not.toContain(API_KEY);
    const y = await connect({ baseUrl: mock.url, apiKey: undefined });
    expect((await call(y.client, "idemcore_chat", { prompt: "hi" })).text).toMatch(/IDEMCORE_API_KEY is not set/);
  });
});

describe("stdio entry point", () => {
  it("starts over stdio and answers a chat via the mock", async () => {
    const mock = await startMock({ withTextHash: true });
    const t = new StdioClientTransport({ command: process.execPath, args: [new URL("../dist/index.js", import.meta.url).pathname],
      env: { PATH: process.env.PATH ?? "", IDEMCORE_BASE_URL: mock.url, IDEMCORE_API_KEY: API_KEY }, stderr: "pipe" });
    const client = new Client({ name: "stdio-test", version: "0" });
    await client.connect(t);
    const { json } = await call(client, "idemcore_chat", { prompt: "What is the capital of France?" });
    expect(json.verification.verdict).toBe("VERIFIED");
    await client.close(); await mock.close();
  }, 20000);
});

function writeKeys(keys: unknown): string {
  const p = join(mkdtempSync(join(tmpdir(), "ick-")), "keys.json");
  writeFileSync(p, JSON.stringify({ keys }));
  return p;
}
