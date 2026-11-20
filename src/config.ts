import { readFileSync } from "node:fs";
import { importKeySet, type TrustedKey } from "./keys.js";
import { DEFAULT_TRUSTED_KEYS } from "./default-keys.js";

export interface Config {
  baseUrl: string;
  apiKey?: string;
  keysUrl?: string;          // where to fetch the issuer's public keys (JWKS)
  trustedKeysFile?: string;  // local JWK / JWKS file, preferred for offline use
  defaultKeys?: boolean;     // bundled Idemcore production keys (default: on)
  exportDir: string;
  timeoutMs: number;
  fetchImpl: typeof fetch;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const baseUrl = (env.IDEMCORE_BASE_URL || "https://api.idemcore.net").replace(/\/+$/, "");
  return {
    baseUrl,
    apiKey: env.IDEMCORE_API_KEY || undefined,
    keysUrl: env.IDEMCORE_KEYS_URL === "off" ? undefined : (env.IDEMCORE_KEYS_URL || `${baseUrl}/v1/keys`),
    trustedKeysFile: env.IDEMCORE_TRUSTED_KEYS || undefined,
    defaultKeys: env.IDEMCORE_DEFAULT_KEYS !== "off",
    exportDir: env.IDEMCORE_EXPORT_DIR || "./idemcore-exports",
    timeoutMs: Number(env.IDEMCORE_TIMEOUT_MS || 120000),
    fetchImpl: fetch,
  };
}

/** Trusted key store: bundled production keys, a local file, then the issuer's published key set (cached). */
export class KeyStore {
  private cache: TrustedKey[] | null = null;
  constructor(private cfg: Config) {}

  async get(): Promise<{ keys: TrustedKey[]; warnings: string[] }> {
    if (this.cache) return { keys: this.cache, warnings: [] };
    const keys: TrustedKey[] = [], warnings: string[] = [];
    if (this.cfg.defaultKeys !== false) keys.push(...await importKeySet(DEFAULT_TRUSTED_KEYS, "bundled:idemcore-production"));
    if (this.cfg.trustedKeysFile) {
      try {
        for (const k of await importKeySet(JSON.parse(readFileSync(this.cfg.trustedKeysFile, "utf8")), `file:${this.cfg.trustedKeysFile}`)) if (!keys.some((x) => x.keyId === k.keyId)) keys.push(k);
      } catch (e) { warnings.push(`could not load trusted keys file: ${(e as Error).message}`); }
    }
    if (this.cfg.keysUrl) {
      try {
        const r = await this.cfg.fetchImpl(this.cfg.keysUrl, { signal: AbortSignal.timeout(this.cfg.timeoutMs) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        for (const k of await importKeySet(await r.json(), this.cfg.keysUrl)) if (!keys.some((x) => x.keyId === k.keyId)) keys.push(k);
      } catch (e) { warnings.push(`could not fetch issuer keys from ${this.cfg.keysUrl}: ${(e as Error).message}`); }
    }
    if (keys.length) this.cache = keys;
    return { keys, warnings };
  }
}
