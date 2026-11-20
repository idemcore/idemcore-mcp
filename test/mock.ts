// Local mock of the Idemcore API that issues receipts signed with an ephemeral key.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { b64u, hex, sha256 } from "../src/bytes.js";
import { keyIdFor } from "../src/keys.js";
import { promptHash, textHash, tokenHash, taggedHash } from "../src/hash.js";
import { signingPayload } from "../src/receipt.js";
import { canonicalBytes } from "../src/canonical.js";

export const API_KEY = "test-key-should-never-appear-in-output-7f3a";

export async function startMock(opts: { withTextHash?: boolean; tamper?: boolean; receiptInHeader?: boolean } = {}) {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const keyId = await keyIdFor(raw);
  const store = new Map<string, Record<string, unknown>>();
  const seen: { path: string; auth?: string; body?: any }[] = [];

  async function sign(fields: Record<string, unknown>) {
    const r: Record<string, unknown> = { receipt_version: "r2", receipt_id: "rcpt_" + hex(crypto.getRandomValues(new Uint8Array(12))),
      issued_at: new Date().toISOString(), ...fields, key_id: keyId };
    r.signature = b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, signingPayload(r) as BufferSource)));
    return r;
  }

  const server: Server = createServer(async (req, res) => {
    let raw = ""; for await (const c of req) raw += c;
    const body = raw ? JSON.parse(raw) : undefined;
    seen.push({ path: req.url!, auth: req.headers.authorization, body });
    const send = (code: number, data: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(code, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(data));
    };
    if (req.url === "/v1/keys") return send(200, { keys: [{ kty: "OKP", crv: "Ed25519", x: jwk.x, kid: keyId }] });
    if (req.headers.authorization !== `Bearer ${API_KEY}`) return send(401, { error: { message: "invalid api key" } });
    if (req.url === "/v1/chat/completions" && req.method === "POST") {
      const answer = "The capital of France is Paris.";
      const ids = [785, 6722, 315, 9625, 374, 12095, 13];
      const privacy = body.idemcore?.privacy ?? "full";
      const salt = privacy === "full" ? new Uint8Array(0) : crypto.getRandomValues(new Uint8Array(16));
      const fields: Record<string, unknown> = {
        tenant_id: "tnt_test", model_id: body.model ?? "qwen2.5-7b-instruct-q4", weights_hash: "ab".repeat(32),
        engine_version: "0.2.0", engine_build: "mock", privacy, prompt_hash: await promptHash(body.messages, salt),
        params_hash: await taggedHash("params", canonicalBytes({ max_tokens: body.max_tokens ?? 64 })), variant: body.idemcore?.seed ?? 0,
        decoding: "greedy", prompt_tokens: 20, output_tokens: ids.length, output_token_hash: await tokenHash(ids, salt),
        chain_digest: hex(await sha256(new Uint8Array([1]))), chain_check: "0123456789abcdef", log_ref: "log_none", finish_reason: "stop",
      };
      if (opts.withTextHash) fields.output_text_hash = await textHash(answer, salt);
      const receipt = await sign(fields);
      store.set(receipt.receipt_id as string, receipt);
      const shown = opts.tamper ? { ...receipt, model_id: "some-other-model" } : receipt;
      const data: Record<string, unknown> = { id: "chatcmpl-1", object: "chat.completion", model: fields.model_id,
        choices: [{ index: 0, message: { role: "assistant", content: answer }, finish_reason: "stop" }],
        usage: { prompt_tokens: 20, completion_tokens: ids.length, total_tokens: 27 } };
      if (privacy === "hash_only") data.idemcore_salt = b64u(salt);
      if (opts.receiptInHeader) return send(200, data, { "idemcore-receipt": Buffer.from(JSON.stringify(shown)).toString("base64url") });
      return send(200, { ...data, idemcore_receipt: shown });
    }
    const m = req.url!.match(/^\/v1\/receipts\/([^/?]+)/);
    if (m && req.method === "GET") {
      const r = store.get(decodeURIComponent(m[1]));
      return r ? send(200, { receipt: r }) : send(404, { error: { message: "receipt not found" } });
    }
    if (req.url === "/v1/audit/export" && req.method === "POST") return send(200, { events: [], roots: [], receipts: [...store.values()] });
    send(404, { error: { message: "not found" } });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url, keyId, seen, store, close: () => new Promise<void>((r) => server.close(() => r())) };
}
