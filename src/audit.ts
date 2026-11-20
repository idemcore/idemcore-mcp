// Offline checks for audit exports: hash-chained events and signed daily Merkle roots.
import { canonicalBytes } from "./canonical.js";
import { b64uDec, concat, hex, sha256, unhex, utf8 } from "./bytes.js";
import type { TrustedKey } from "./keys.js";

const GENESIS = "0".repeat(64);
const EVENT_FIELDS = ["tenant_id", "seq", "ts", "event_type", "receipt_id", "actor", "payload", "prev_hash"];
const ROOT_DOMAIN = utf8("idemcore-audit-root/r1\n");

export type AuditEvent = Record<string, unknown> & { seq: number; prev_hash: string; event_hash: string };

export async function eventHash(ev: Record<string, unknown>): Promise<string> {
  const body: Record<string, unknown> = {};
  for (const k of EVENT_FIELDS) body[k] = ev[k] === undefined ? null : ev[k];
  return hex(await sha256(concat(utf8("idemcore/audit/r1\0"), canonicalBytes(body))));
}

export async function verifyEventChain(events: AuditEvent[]): Promise<string[]> {
  const errs: string[] = [];
  let prev = GENESIS, seq: number | null = null;
  for (const ev of events) {
    if (seq !== null && ev.seq !== seq + 1) errs.push(`seq gap at ${ev.seq}`);
    if (ev.prev_hash !== prev) errs.push(`prev_hash mismatch at seq ${ev.seq}`);
    if ((await eventHash(ev)) !== ev.event_hash) errs.push(`event_hash mismatch at seq ${ev.seq}`);
    prev = ev.event_hash; seq = ev.seq;
  }
  return errs;
}

async function mth(items: Uint8Array[]): Promise<Uint8Array> {
  if (items.length === 1) return sha256(concat(new Uint8Array([0]), items[0]));
  let k = 1;
  while (k * 2 < items.length) k *= 2;
  return sha256(concat(new Uint8Array([1]), await mth(items.slice(0, k)), await mth(items.slice(k))));
}

export async function merkleRoot(hashesHex: string[]): Promise<string> {
  if (!hashesHex.length) return hex(await sha256(new Uint8Array(0)));
  return hex(await mth(hashesHex.map(unhex)));
}

export async function verifyRoot(root: Record<string, unknown>, events: AuditEvent[], keys: TrustedKey[]): Promise<string[]> {
  const errs: string[] = [];
  const pk = keys.find((k) => k.keyId === root.key_id);
  const { signature, ...body } = root;
  if (!pk) errs.push(`unknown root key_id ${String(root.key_id)}`);
  else {
    let ok = false;
    try { ok = await pk.verify(b64uDec(String(signature)), concat(ROOT_DOMAIN, canonicalBytes(body))); } catch { ok = false; }
    if (!ok) errs.push("root signature does not verify");
  }
  if ((await merkleRoot(events.map((e) => e.event_hash))) !== root.merkle_root) errs.push("merkle_root mismatch");
  return errs;
}
