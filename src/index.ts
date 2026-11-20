#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { configFromEnv } from "./config.js";
import { createServer, VERSION } from "./server.js";

if (process.argv.includes("--version")) { console.log(VERSION); process.exit(0); }
const server = createServer(configFromEnv());
await server.connect(new StdioServerTransport());
console.error(`idemcore-mcp ${VERSION} ready on stdio`);
