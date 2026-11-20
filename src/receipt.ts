// Offline verification of Idemcore receipts r1 and r2 (L1 signature, L2 chain, disclosure).
// r2 renames three r1 fields (one of them seed→variant); signing is identical.
import { canonicalBytes, canonicalString } from "./canonical.js";
import { isSafeWholeNumber } from "./whole.js";
import { b64uDec, concat, utf8 } from "./bytes.js";
import { logDigests, promptHash, textHash, tokenHash } from "./hash.js";
import type { TrustedKey } from "./keys.js";

export const RECEIPT_VERSION = "r2";
export const RECEIPT_VERSIONS = ["r1", "r2"];
const SIG_DOMAIN = utf8("idemcore-receipt/r1\n");
const HEX64 = /^[0-9a-f]{64}$/, HEX16 = /^[0-9a-f]{16}$/;

const COMMON: Record<string, "str" | "int"> = {
  receipt_version: "str", receipt_id: "str", issued_at: "str", tenant_id: "str", model_id: "str",
  weights_hash: "str", engine_build: "str", privacy: "str", prompt_hash: "str",
  params_hash: "str", decoding: "str", prompt_tokens: "int", output_tokens: "int",
  output_token_hash: "str", chain_digest: "str", log_ref: "str", key_id: "str", signature: "str",
};
const REQUIRED_R2: Record<string, "str" | "int"> = { ...COMMON, variant: "int", chain_check: "str", engine_version: "str" };
// r1 receipts carry two more string fields under their earlier names (the r2 chain_check and
// engine_version); they are bound by the signature.
const REQUIRED_R1: Record<string, "str" | "int"> = { ...COMMON, seed: "int" };
const R1_LEGACY_COUNT = 2;
// output_text_hash is a proposed optional field (see EMBED_SPEC in the extension repo).
const OPTIONAL: Record<string, "str"> = { finish_reason: "str", request_id: "str", output_text_hash: "str" };
const HASH_FIELDS = ["weights_hash", "prompt_hash", "params_hash", "output_token_hash", "chain_digest"];

const r1Legacy = (r: Record<string, unknown>) =>
  Object.keys(r).filter((k) => !(k in REQUIRED_R1) && !(k in OPTIONAL)).sort();
/** Name of the 16-hex chain check field for this receipt's version (`chain_check` in r2; its earlier name in r1). */
export function chainCheckField(r: Record<string, unknown>): string {
  if (r.receipt_version === "r2") return "chain_check";
  for (const k of r1Legacy(r)) if (typeof r[k] === "string" && HEX16.test(r[k] as string)) return k;
  return "chain_check";
}
/** Value of an r2 field name, also for r1 receipts (variant, chain_check, engine_version read from their r1 names). */
export function receiptField(r: Record<string, unknown>, name: string): unknown {
  if (name in r || r.receipt_version !== "r1") return r[name];
  if (name === "variant") return r.seed;
  if (name === "chain_check") return r[chainCheckField(r)];
  if (name === "engine_version") {
    const rest = r1Legacy(r).filter((k) => k !== chainCheckField(r));
    return rest.length === 1 ? r[rest[0]] : undefined;
  }
  return undefined;
}

export type Receipt = Record<string, unknown>;
export interface Result { level: string; ok: boolean; errors: string[]; [k: string]: unknown }
const result = (level: string, errors: string[], extra: Record<string, unknown> = {}): Result =>
  ({ level, ok: errors.length === 0, errors, ...extra });

export function signingPayload(r: Receipt): Uint8Array {
  const { signature: _s, ...body } = r;
  return concat(SIG_DOMAIN, canonicalBytes(body));
}

export function checkFormat(r: unknown): string[] {
  if (typeof r !== "object" || r === null || Array.isArray(r)) return ["receipt is not an object"];
  const o = r as Record<string, unknown>, errs: string[] = [];
  if (!RECEIPT_VERSIONS.includes(o.receipt_version as string)) return [`unsupported receipt_version ${String(o.receipt_version)}`];
  const REQUIRED = o.receipt_version === "r2" ? REQUIRED_R2 : REQUIRED_R1, CHK = chainCheckField(o);
  for (const [k, t] of Object.entries(REQUIRED)) {
    if (!(k in o)) errs.push(`missing field ${k}`);
    else if (t === "int" ? !isSafeWholeNumber(o[k]) : typeof o[k] !== "string") errs.push(`field ${k} must be ${t}`);
  }
  const extra = Object.keys(o).filter((k) => !(k in REQUIRED) && !(k in OPTIONAL));
  if (o.receipt_version === "r1") {
    const strs = extra.filter((k) => typeof o[k] === "string");
    for (const k of extra) if (!strs.includes(k)) errs.push(`unknown field ${k}`);
    if (strs.length !== R1_LEGACY_COUNT) errs.push(`r1 receipt must have ${R1_LEGACY_COUNT} more string fields, found ${strs.length}`);
  } else for (const k of extra) errs.push(`unknown field ${k}`);
  for (const k of Object.keys(OPTIONAL)) if (k in o && typeof o[k] !== "string") errs.push(`field ${k} must be str`);
  if (errs.length) return errs;
  for (const k of HASH_FIELDS) if (!HEX64.test(o[k] as string)) errs.push(`${k} must be 64 lowercase hex`);
  if ("output_text_hash" in o && !HEX64.test(o.output_text_hash as string)) errs.push("output_text_hash must be 64 lowercase hex");
  if (typeof o[CHK] !== "string" || !HEX16.test(o[CHK] as string)) errs.push(`${CHK} must be 16 lowercase hex`);
  if (o.privacy !== "hash_only" && o.privacy !== "full") errs.push("privacy must be hash_only or full");
  if ((o.prompt_tokens as number) < 1 || (o.output_tokens as number) < 0) errs.push("token counts out of range");
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$/.test(o.issued_at as string)) errs.push("issued_at must be RFC 3339 UTC (Z)");
  try { canonicalString(o); } catch (e) { errs.push((e as Error).message); }
  return errs;
}

export async function verifyL1(r: unknown, keys: TrustedKey[]): Promise<Result> {
  const errs = checkFormat(r);
  if (errs.length) return result("L1", errs);
  const rc = r as Receipt;
  const pk = keys.find((k) => k.keyId === rc.key_id);
  if (!pk) return result("L1", [`unknown key_id ${String(rc.key_id)} (not in the trusted key set)`]);
  let sig: Uint8Array;
  try { sig = b64uDec(rc.signature as string); } catch { return result("L1", ["signature is not base64url"]); }
  if (sig.length !== 64 || !(await pk.verify(sig, signingPayload(rc)))) return result("L1", ["signature does not verify"]);
  return result("L1", [], { key_id: pk.keyId, key_source: pk.source });
}

export async function verifyL2(r: Receipt, logText: string): Promise<Result> {
  let d;
  try { d = await logDigests(logText); } catch (e) { return result("L2", [`log parse error: ${(e as Error).message}`]); }
  const errs: string[] = [];
  if (d.chain_digest !== r.chain_digest) errs.push("chain_digest mismatch");
  const want = Number(r.prompt_tokens ?? 0) + Number(r.output_tokens ?? 0);
  if (d.positions !== want) errs.push(`log covers ${d.positions} positions, receipt says ${want}`);
  return result("L2", errs, { positions: d.positions });
}

export interface Disclosure { messages?: unknown; outputIds?: number[]; outputText?: string; salt?: Uint8Array | null }

export async function verifyDisclosure(r: Receipt, d: Disclosure): Promise<Result> {
  const salt = r.privacy === "full" ? new Uint8Array(0) : d.salt;
  if (salt == null) return result("disclosure", ["salt required for hash_only receipts"]);
  const errs: string[] = [], checked: string[] = [];
  if (d.messages !== undefined) {
    checked.push("prompt_hash");
    if ((await promptHash(d.messages, salt)) !== r.prompt_hash) errs.push("prompt_hash mismatch");
  }
  if (d.outputIds !== undefined) {
    checked.push("output_token_hash");
    if ((await tokenHash(d.outputIds, salt)) !== r.output_token_hash) errs.push("output_token_hash mismatch");
  }
  if (d.outputText !== undefined) {
    if (typeof r.output_text_hash !== "string") {
      errs.push("receipt has no output_text_hash; displayed text cannot be bound (use output token ids instead)");
    } else {
      checked.push("output_text_hash");
      if ((await textHash(d.outputText, salt)) !== r.output_text_hash) errs.push("output_text_hash mismatch");
    }
  }
  return result("disclosure", errs, { checked });
}
