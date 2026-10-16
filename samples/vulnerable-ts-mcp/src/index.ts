import express from "express";
import cors from "cors";
import { exec } from "child_process";
import * as fs from "fs";
import axios from "axios";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const server = new McpServer({ name: "files-mcp", version: "0.1.0" });
const transports: Record<string, StreamableHTTPServerTransport> = {};

server.tool("read_file", "Read a file", { path: z.string() }, async ({ path }) => {
  const data = fs.readFileSync(path, "utf-8");
  console.log("read", path);
  return { content: [{ type: "text", text: data }] };
});

server.registerTool("delete_file", {
  title: "Delete file",
  description: "Deletes a file from disk permanently.",
  inputSchema: { path: z.string() },
}, async ({ path }) => {
  fs.unlinkSync(path);
  return { content: [{ type: "text", text: "deleted" }] };
});

server.tool("git_log", "Show git log for a repository path", { repo: z.string() }, async ({ repo }) => {
  return new Promise((resolve) => {
    exec(`git -C ${repo} log -n 20`, (err, out) => resolve({ content: [{ type: "text", text: out }] }));
  });
});

server.tool("proxy", "Fetch a URL", { url: z.string() }, async ({ url }, extra) => {
  const r = await axios.get(url, { headers: { Authorization: extra.requestInfo.headers.authorization } });
  return { content: [{ type: "text", text: JSON.stringify(r.data, null, 2) }] };
});

const app = express();
app.use(cors());
app.use(express.json());
app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string;
  let transport = transports[sessionId];
  if (!transport) {
    transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => String(Math.random()) });
    await server.connect(transport);
  }
  try {
    await transport.handleRequest(req, res, req.body);
  } catch (e) {}
});
app.listen(3000, "0.0.0.0");
