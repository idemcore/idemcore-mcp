import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ApiError, extractReceipt, IdemcoreApi } from "./api.js";
import { KeyStore, type Config } from "./config.js";
import { importKeySet, type TrustedKey } from "./keys.js";
import { b64uDec } from "./bytes.js";
import { verifyDisclosure, verifyL1, verifyL2, type Receipt, type Result } from "./receipt.js";
import { verifyEventChain, verifyRoot, type AuditEvent } from "./audit.js";

import { VERSION } from "./version.js";

export { VERSION };

type ToolOut = { content: { type: "text"; text: string }[]; isError?: boolean };
const out = (summary: string, data: unknown, isError = false): ToolOut =>
  ({ content: [{ type: "text", text: `${summary}\n\n${JSON.stringify(data, null, 2)}` }], ...(isError ? { isError } : {}) });
const fail = (e: unknown): ToolOut => out(`Error: ${(e as Error).message}`, { error: (e as Error).message, status: e instanceof ApiError ? e.status : undefined }, true);

function parseReceipt(x: unknown): Receipt {
  if (typeof x === "string") {
    const s = x.trim();
    try { return JSON.parse(s); } catch { /* maybe base64url */ }
    return JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
  }
  if (x && typeof x === "object" && !Array.isArray(x)) {
    const o = x as Record<string, unknown>;
    if (o.receipt && typeof o.receipt === "object") return o.receipt as Receipt; // embed envelope
    return o;
  }
  throw new Error("receipt must be a JSON object or string");
}

function verdict(parts: Result[]): "VERIFIED" | "FAILED" | "UNVERIFIED" {
  if (parts.some((p) => !p.ok && !String(p.errors[0] ?? "").startsWith("unknown key_id"))) return "FAILED";
  if (parts.some((p) => !p.ok)) return "UNVERIFIED";
  return "VERIFIED";
}

export interface VerifyInput {
  receipt: unknown; log_text?: string; log_path?: string; messages?: unknown; output_ids?: number[];
  output_text?: string; salt_b64u?: string; extra_keys?: unknown;
}

export async function verifyAll(input: VerifyInput, keyStore: KeyStore) {
  const receipt = parseReceipt(input.receipt);
  const { keys, warnings } = await keyStore.get();
  let all: TrustedKey[] = keys;
  if (input.extra_keys !== undefined) all = [...keys, ...await importKeySet(input.extra_keys, "caller-supplied")];
  const checks: Result[] = [await verifyL1(receipt, all)];
  const logText = input.log_text ?? (input.log_path ? readFileSync(input.log_path, "utf8") : undefined);
  if (logText !== undefined) checks.push(await verifyL2(receipt, logText));
  if (input.messages !== undefined || input.output_ids !== undefined || input.output_text !== undefined) {
    checks.push(await verifyDisclosure(receipt, {
      messages: input.messages, outputIds: input.output_ids, outputText: input.output_text,
      salt: input.salt_b64u !== undefined ? b64uDec(input.salt_b64u) : null,
    }));
  }
  const v = verdict(checks);
  if (checks[0].ok && checks[0].key_source === "caller-supplied") warnings.push("signature checked against a caller-supplied key, not an Idemcore-published key");
  return {
    verdict: v,
    receipt_id: receipt.receipt_id, model_id: receipt.model_id, issued_at: receipt.issued_at, privacy: receipt.privacy,
    checks, warnings,
    note: logText === undefined ? "L2 not run: pass log_text or log_path to recompute the token-log chain" : undefined,
  };
}

const message = z.object({ role: z.enum(["system", "user", "assistant"]), content: z.string() });

export function createServer(cfg: Config): McpServer {
  const api = new IdemcoreApi(cfg);
  const keyStore = new KeyStore(cfg);
  const server = new McpServer({ name: "idemcore", version: VERSION });

  server.registerTool("idemcore_chat", {
    title: "Chat with a signed receipt",
    description: "Send a chat request to an open model running on Idemcore (OpenAI-compatible API). Returns the answer plus a signed receipt that proves which model, inputs and settings produced it, and checks the receipt signature locally.",
    inputSchema: {
      prompt: z.string().optional().describe("User message. Use this or `messages`."),
      messages: z.array(message).optional().describe("Full chat history in OpenAI format."),
      system: z.string().optional().describe("Optional system message, prepended when using `prompt`."),
      model: z.string().optional().describe("Model id; defaults to IDEMCORE_MODEL or the server default."),
      max_tokens: z.number().int().positive().max(32768).optional(),
      temperature: z.number().min(0).max(2).optional(),
      seed: z.number().int().optional().describe("Sampling seed recorded in the receipt."),
      privacy: z.enum(["hash_only", "full"]).optional().describe("hash_only (default on the API) keeps only salted hashes."),
      token_log: z.enum(["none", "per_token"]).optional().describe("per_token keeps a per-token log so L2 can be checked later."),
      verify: z.boolean().default(true).describe("Check the receipt signature locally (offline)."),
    },
  }, async (a) => {
    try {
      const messages = a.messages ?? [...(a.system ? [{ role: "system" as const, content: a.system }] : []), ...(a.prompt !== undefined ? [{ role: "user" as const, content: a.prompt }] : [])];
      if (!messages.length) throw new Error("pass `prompt` or `messages`");
      const model = a.model ?? process.env.IDEMCORE_MODEL;
      const idem: Record<string, unknown> = {};
      if (a.privacy) idem.privacy = a.privacy;
      if (a.token_log) idem.token_log = a.token_log;
      if (a.seed !== undefined) idem.seed = a.seed;
      const body: Record<string, unknown> = { messages, ...(model ? { model } : {}), stream: false };
      if (a.max_tokens !== undefined) body.max_tokens = a.max_tokens;
      if (a.temperature !== undefined) body.temperature = a.temperature;
      if (a.seed !== undefined) body.seed = a.seed;
      if (Object.keys(idem).length) body.idemcore = idem;
      const { data, headers } = await api.chat(body);
      const answer: string = data?.choices?.[0]?.message?.content ?? "";
      const receipt = extractReceipt(data, headers);
      let verification: unknown = receipt ? undefined : { verdict: "UNVERIFIED", checks: [], warnings: ["the API response carried no receipt"] };
      if (receipt && a.verify) {
        const salt = typeof data?.idemcore_salt === "string" ? data.idemcore_salt : undefined;
        verification = await verifyAll({
          receipt, messages,
          ...(typeof receipt.output_text_hash === "string" && (receipt.privacy === "full" || salt) ? { output_text: answer, salt_b64u: salt } : {}),
        }, keyStore);
      }
      const v = (verification as { verdict?: string } | undefined)?.verdict ?? "NOT_CHECKED";
      return out(`${answer}\n\n— Idemcore receipt ${String(receipt?.receipt_id ?? "missing")}: ${v}`, {
        answer, model: data?.model, finish_reason: data?.choices?.[0]?.finish_reason, usage: data?.usage,
        receipt, verification,
      });
    } catch (e) { return fail(e); }
  });

  server.registerTool("idemcore_verify_receipt", {
    title: "Verify a receipt offline",
    description: "Verify an Idemcore receipt without calling the API: L1 checks format and the Ed25519 signature against trusted Idemcore keys; L2 recomputes the token-log chain digests from a log; optional disclosure checks that a prompt, token ids or displayed text match the receipt's hashes.",
    inputSchema: {
      receipt: z.union([z.string(), z.record(z.string(), z.any())]).describe("Receipt JSON (object, JSON string, base64url JSON, or an embed envelope {receipt, ...})."),
      log_text: z.string().optional().describe("Per-token log text for L2."),
      log_path: z.string().optional().describe("Path to a per-token log file for L2."),
      messages: z.array(message).optional().describe("Disclosed prompt messages to check against prompt_hash."),
      output_ids: z.array(z.number().int().nonnegative()).optional().describe("Disclosed output token ids to check against output_token_hash."),
      output_text: z.string().optional().describe("Displayed answer text to check against output_text_hash (if the receipt carries it)."),
      salt_b64u: z.string().optional().describe("Salt (base64url) for hash_only receipts; not needed for privacy=full."),
      extra_keys: z.any().optional().describe("Extra public JWK / JWKS to trust for this call (e.g. a self-hosted signer)."),
    },
  }, async (a) => {
    try {
      const r = await verifyAll(a as VerifyInput, keyStore);
      return out(`Receipt ${String(r.receipt_id)}: ${r.verdict}`, r, r.verdict === "FAILED");
    } catch (e) { return fail(e); }
  });

  server.registerTool("idemcore_get_receipt", {
    title: "Fetch a stored receipt",
    description: "Fetch a receipt (and optionally its per-token log) from the tenant's Idemcore receipt store, then verify it locally.",
    inputSchema: {
      receipt_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
      include_log: z.boolean().default(false),
      verify: z.boolean().default(true),
    },
  }, async (a) => {
    try {
      const { data, headers } = await api.getReceipt(a.receipt_id, a.include_log);
      const receipt = (data?.receipt && typeof data.receipt === "object") ? data.receipt : (extractReceipt(data, headers) ?? data);
      const logText: string | undefined = typeof data?.log_text === "string" ? data.log_text : undefined;
      const verification = a.verify ? await verifyAll({ receipt, log_text: logText }, keyStore) : undefined;
      return out(`Receipt ${a.receipt_id}: ${verification?.verdict ?? "NOT_CHECKED"}`, { receipt, has_log: logText !== undefined, verification });
    } catch (e) { return fail(e); }
  });

  server.registerTool("idemcore_export_audit", {
    title: "Export an audit bundle",
    description: "Export the tenant's receipts and audit events for a time range, save them to a local file, and check the event hash chain and signed daily Merkle roots offline.",
    inputSchema: {
      from: z.string().describe("Start (RFC 3339 or YYYY-MM-DD, UTC)."),
      to: z.string().describe("End (RFC 3339 or YYYY-MM-DD, UTC)."),
      include_logs: z.boolean().default(false),
      save: z.boolean().default(true).describe("Write the bundle under IDEMCORE_EXPORT_DIR."),
    },
  }, async (a) => {
    try {
      const { data } = await api.exportAudit({ from: a.from, to: a.to, include_logs: a.include_logs, format: "json" });
      const check = await checkBundle(data, keyStore);
      let saved: string | undefined;
      if (a.save) {
        const dir = resolve(cfg.exportDir);
        mkdirSync(dir, { recursive: true });
        saved = join(dir, `idemcore-audit-${a.from}_${a.to}.json`.replace(/[^A-Za-z0-9_.-]/g, "_").replace(/^_+/, ""));
        saved = join(dir, saved.split("/").pop()!);
        writeFileSync(saved, JSON.stringify(data, null, 1));
      }
      return out(`Audit export ${a.from} → ${a.to}: ${check.verdict}`, { saved_to: saved, ...check });
    } catch (e) { return fail(e); }
  });

  server.registerTool("idemcore_verify_audit", {
    title: "Verify an audit bundle offline",
    description: "Check an exported audit bundle (JSON file with `events`, `roots` and optional `receipts`) offline: event hash chain, signed Merkle roots and every receipt signature.",
    inputSchema: { path: z.string().describe("Path to the exported bundle JSON.") },
  }, async (a) => {
    try {
      const check = await checkBundle(JSON.parse(readFileSync(a.path, "utf8")), keyStore);
      return out(`Audit bundle ${a.path}: ${check.verdict}`, check, check.verdict === "FAILED");
    } catch (e) { return fail(e); }
  });

  server.registerTool("idemcore_trusted_keys", {
    title: "List trusted signing keys",
    description: "Show which Idemcore public keys this server trusts for receipt signatures and where each came from.",
    inputSchema: {},
  }, async () => {
    const { keys, warnings } = await keyStore.get();
    return out(`${keys.length} trusted key(s)`, { keys: keys.map((k) => ({ key_id: k.keyId, source: k.source, jwk: k.jwk })), warnings, base_url: cfg.baseUrl });
  });

  return server;
}

export async function checkBundle(data: any, keyStore: KeyStore) {
  const { keys, warnings } = await keyStore.get();
  const events: AuditEvent[] = Array.isArray(data?.events) ? data.events : [];
  const roots: Record<string, unknown>[] = Array.isArray(data?.roots) ? data.roots : [];
  const receipts: Receipt[] = Array.isArray(data?.receipts) ? data.receipts : [];
  const errors: string[] = [];
  const byTenant = new Map<string, AuditEvent[]>();
  for (const e of events) { const t = String(e.tenant_id); if (!byTenant.has(t)) byTenant.set(t, []); byTenant.get(t)!.push(e); }
  for (const [t, evs] of byTenant) for (const er of await verifyEventChain(evs.sort((x, y) => x.seq - y.seq))) errors.push(`tenant ${t}: ${er}`);
  for (const root of roots) {
    const evs = events.filter((e) => e.tenant_id === root.tenant_id && e.seq >= Number(root.first_seq) && e.seq <= Number(root.last_seq));
    for (const er of await verifyRoot(root, evs, keys)) errors.push(`root ${String(root.day)}: ${er}`);
  }
  let receiptsOk = 0;
  for (const r of receipts) {
    const res = await verifyL1(r, keys);
    if (res.ok) receiptsOk++; else errors.push(`receipt ${String(r.receipt_id)}: ${res.errors.join("; ")}`);
  }
  return {
    verdict: (errors.length ? "FAILED" : "VERIFIED") as "FAILED" | "VERIFIED",
    events: events.length, roots: roots.length, receipts: receipts.length, receipts_ok: receiptsOk, errors, warnings,
  };
}
