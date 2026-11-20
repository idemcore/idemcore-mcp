// Thin client for the Idemcore OpenAI-compatible API. The API key is sent only
// in the Authorization header and is never included in tool output or errors.
import type { Config } from "./config.js";
import { VERSION } from "./version.js";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export class IdemcoreApi {
  constructor(private cfg: Config) {}

  private headers(json = true): Record<string, string> {
    if (!this.cfg.apiKey) throw new ApiError(0, "IDEMCORE_API_KEY is not set; add it to the MCP server env");
    const h: Record<string, string> = { authorization: `Bearer ${this.cfg.apiKey}`, "user-agent": `idemcore-mcp/${VERSION}` };
    if (json) h["content-type"] = "application/json";
    return h;
  }

  private async call(method: string, path: string, body?: unknown): Promise<{ data: any; headers: Headers }> {
    const r = await this.cfg.fetchImpl(this.cfg.baseUrl + path, {
      method, headers: this.headers(body !== undefined), body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.cfg.timeoutMs),
    });
    const text = await r.text();
    let data: any = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text.slice(0, 2000) }; }
    if (!r.ok) {
      const msg = data?.error?.message ?? data?.error ?? data?.message ?? text.slice(0, 300);
      throw new ApiError(r.status, `Idemcore API ${method} ${path} failed: HTTP ${r.status} ${typeof msg === "string" ? msg : JSON.stringify(msg)}`);
    }
    return { data, headers: r.headers };
  }

  chat(body: unknown) { return this.call("POST", "/v1/chat/completions", body); }
  getReceipt(id: string, includeLog: boolean) {
    return this.call("GET", `/v1/receipts/${encodeURIComponent(id)}${includeLog ? "?include_log=1" : ""}`);
  }
  exportAudit(body: unknown) { return this.call("POST", "/v1/audit/export", body); }
}

/** Receipt from the body field `idemcore_receipt` or the `Idemcore-Receipt` header (JSON or base64url JSON). */
export function extractReceipt(data: any, headers: Headers): Record<string, unknown> | null {
  if (data && typeof data.idemcore_receipt === "object" && data.idemcore_receipt) return data.idemcore_receipt;
  const h = headers.get("idemcore-receipt");
  if (!h) return null;
  try { return JSON.parse(h); } catch { /* fall through */ }
  try { return JSON.parse(Buffer.from(h, "base64url").toString("utf8")); } catch { return null; }
}
