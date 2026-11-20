# Idemcore MCP server

Give any MCP-capable assistant or agent (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Codex and others) two abilities:

1. **Chat with a receipt.** Call an open model running on Idemcore and get back the answer together with a signed receipt that records which model, weights, inputs and settings produced it.
2. **Verify a receipt.** Check any Idemcore receipt locally, with no network access and no account.

Status: 0.1.5. Published as `@idemcore/mcp` and listed in the MCP Registry as `net.idemcore/mcp`. Verifies receipt formats r1 and r2.

Install guide: https://idemcore.net/integrations/mcp

## Tools

| Tool | Network | What it does |
|---|---|---|
| `idemcore_chat` | API key | Sends an OpenAI-compatible chat request, returns the answer, the receipt and a local signature check. Options: `privacy` (`hash_only` / `full`), `token_log` (`none` / `per_token`), `seed`, `model`, `max_tokens`, `temperature`. |
| `idemcore_verify_receipt` | none | **L1**: format and Ed25519 signature against trusted Idemcore keys. **L2**: recomputes the SHA-256 `chain_digest` from a public token log (`log_text` or `log_path`; one `pi j h hc` line per position plus an `ALL` line) and checks the position count. Format v2 logs are checked with the open verifier `idemcore-verify` 0.4.0 or later. **Disclosure**: checks a prompt, output token ids or the displayed answer text against the receipt's hashes (salt needed for `hash_only`). |
| `idemcore_get_receipt` | API key | Fetches a stored receipt (optionally with its per-token log) and verifies it. |
| `idemcore_export_audit` | API key | Exports receipts and audit events for a time range, saves the bundle locally and checks the event hash chain and the signed daily Merkle roots. |
| `idemcore_verify_audit` | none | Checks a saved audit bundle offline. |
| `idemcore_trusted_keys` | optional | Lists the public keys used for signature checks and where each came from. |

Verdicts: `VERIFIED` (all requested checks passed), `FAILED` (a signature, hash or chain does not match: the receipt or data was altered), `UNVERIFIED` (the signing key is not trusted or no key set could be loaded).

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `IDEMCORE_API_KEY` | (none) | Your Idemcore API key. Needed only for chat, get and export. Sent only in the `Authorization` header, never echoed in tool output. |
| `IDEMCORE_BASE_URL` | `https://api.idemcore.net` | API base URL (use your self-hosted gateway if you run Idemcore on-prem). |
| `IDEMCORE_MODEL` | (server default) | Default model id for `idemcore_chat`. |
| `IDEMCORE_TRUSTED_KEYS` | (none) | Path to a JWK / JWKS file of trusted signing keys. Use this for fully offline verification or for a self-hosted signer. |
| `IDEMCORE_DEFAULT_KEYS` | `on` | The Idemcore production public key (`ed25519:2fab59995ac55e4f`, public half only) is bundled in `src/default-keys.ts` and trusted by default. Set `off` to trust only your file / `IDEMCORE_KEYS_URL`. |
| `IDEMCORE_KEYS_URL` | `<base>/v1/keys` | Where to fetch the issuer's published keys. Set to `off` to disable. |
| `IDEMCORE_EXPORT_DIR` | `./idemcore-exports` | Where audit exports are saved. |
| `IDEMCORE_TIMEOUT_MS` | `120000` | Request timeout. |

## Install

Requires Node.js 20 or newer. Fastest path:

```bash
npx -y @idemcore/mcp
```

Or clone and build locally: `npm install && npm run build` (produces `dist/index.js`).

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "idemcore": {
      "command": "npx",
      "args": ["-y", "@idemcore/mcp"],
      "env": { "IDEMCORE_API_KEY": "ick_..." }
    }
  }
}
```

### Claude Code

```bash
claude mcp add idemcore -e IDEMCORE_API_KEY=ick_... -- npx -y @idemcore/mcp
```

### Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "idemcore": {
      "command": "npx",
      "args": ["-y", "@idemcore/mcp"],
      "env": { "IDEMCORE_API_KEY": "ick_..." }
    }
  }
}
```

### VS Code (`.vscode/mcp.json`)

```json
{
  "inputs": [{ "type": "promptString", "id": "idemcore-key", "description": "Idemcore API key", "password": true }],
  "servers": {
    "idemcore": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@idemcore/mcp"],
      "env": { "IDEMCORE_API_KEY": "${input:idemcore-key}" }
    }
  }
}
```

### Windsurf (`~/.codeium/windsurf/mcp_config.json`)

Same shape as Cursor (`mcpServers` → `idemcore`).

### Codex CLI (`~/.codex/config.toml`)

```toml
[mcp_servers.idemcore]
command = "node"
args = ["/path/to/idemcore-mcp/dist/index.js"]
env = { IDEMCORE_API_KEY = "ick_..." }
```

### Verify-only (no account)

Leave out `IDEMCORE_API_KEY`. `idemcore_verify_receipt` and `idemcore_verify_audit` still work; set `IDEMCORE_KEYS_URL=off` to run with no network at all (the bundled production key is still trusted; add `IDEMCORE_TRUSTED_KEYS=/path/to/idemcore-keys.json` for other signers).

## Example prompts

- "Ask Idemcore: summarise this contract clause, and keep the receipt."
- "Verify this receipt and tell me whether the answer text matches it."
- "Export last week's audit bundle and check it."

## Receipt API assumptions

The server reads the receipt from the response body field `idemcore_receipt`, or from the `Idemcore-Receipt` header (JSON or base64url JSON). For `hash_only` receipts it uses `idemcore_salt` (base64url) from the response, when present, to check the answer locally. Request options go in the `idemcore` object of the chat request.

Displayed-text checks use the optional receipt field `output_text_hash` (proposed for r1): a tagged SHA-256 of the answer text after normalisation (Unicode NFC, every run of whitespace replaced by one space, leading and trailing space removed). The same rule is used by the Idemcore browser extension, so layout differences on a web page do not cause false alarms while any change of wording does.

## Development

```bash
npm test     # vitest: test vectors + MCP tools against a local mock API + stdio smoke test
```

`vectors/receipts-r2.json` holds test vectors signed with throwaway keys that were discarded after generation; only the public key is stored. Regenerate them with `npm run build && node scripts/make-vectors.mjs`.

A remote (Streamable HTTP) variant for Cloudflare Workers can reuse `createServer()` from `src/server.ts`; it is not deployed yet.

## License

Apache-2.0. Copyright 2026 Don Wick. Contact: don.wick@idemcore.net
