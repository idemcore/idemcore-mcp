// Package version, read from package.json so `--version`, the MCP handshake and the user agent match the release.
import { readFileSync } from "node:fs";

export const VERSION: string = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
