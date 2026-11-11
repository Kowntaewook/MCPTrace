/** Real SDK Streamable HTTP server and client for local process-memory validation. */
import fs from 'node:fs';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

const [role, workdir, portText, marker] = process.argv.slice(2);
const port = Number(portText);
if (!['server', 'client'].includes(role) || !workdir || !Number.isInteger(port)) {
  throw new Error('usage: node node_fixture.mjs server|client WORKDIR PORT [MARKER]');
}
fs.mkdirSync(workdir, { recursive: true });

function journal(message) {
  fs.appendFileSync(`${workdir}/traffic.jsonl`, JSON.stringify(message) + '\n');
}

function logBody(direction, bytes) {
  const body = bytes.toString('utf8');
  const framing = body.trim().startsWith('{') ? 'json' : 'sse';
  if (body.trim().startsWith('{')) {
    journal({ direction, framing, message: JSON.parse(body) });
    return;
  }
  for (const line of body.split(/\r?\n/)) {
    if (line.startsWith('data: ')) {
      journal({ direction, framing, message: JSON.parse(line.slice(6)) });
    }
  }
}

function createServer() {
  const server = new McpServer({ name: 'mcptrace-validation', version: '1.0.0' });
  server.registerTool(
    'echo_marker',
    { description: 'Return the marker supplied by the client', inputSchema: { marker: z.string() } },
    async ({ marker: value }) => ({ content: [{ type: 'text', text: value }] }),
  );
  return server;
}

async function serve() {
  const sessions = new Map();
  function reply(res, id, result, modern = false) {
    const bytes = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, result }));
    logBody('server-to-client', bytes);
    const headers = { 'content-type': 'application/json' };
    if (modern) headers['mcp-protocol-version'] = '2026-07-28';
    res.writeHead(200, headers).end(bytes);
  }
  const web = http.createServer(async (req, res) => {
    try {
      if (req.url !== '/mcp' || req.method !== 'POST') {
        res.writeHead(404).end();
        return;
      }
      const bodyBytes = Buffer.concat(await Array.fromAsync(req));
      const body = JSON.parse(bodyBytes.toString('utf8'));
      logBody('client-to-server', bodyBytes);
      const dotnetMode = req.headers['x-mcptrace-case'];
      if (body.method === 'server/discover' && dotnetMode === 'modern') {
        reply(res, body.id, {
          resultType: 'complete', supportedVersions: ['2026-07-28'],
          capabilities: { tools: {} }, ttlMs: 0, cacheScope: 'private',
          _meta: { 'io.modelcontextprotocol/serverInfo': {
            name: 'mcptrace-validation', version: '1.0.0',
          } },
        }, true);
        return;
      }
      // The v1 server SDK cannot answer a 2026 discovery probe. Return a
      // definite legacy error so modern clients can try initialize promptly.
      if (body.method === 'server/discover') {
        const error = { jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'Method not found' } };
        const bytes = Buffer.from(JSON.stringify(error));
        logBody('server-to-client', bytes);
        res.writeHead(400, { 'content-type': 'application/json' }).end(bytes);
        return;
      }
      if (body.method === 'initialize' && dotnetMode === 'legacy') {
        reply(res, body.id, {
          protocolVersion: '2025-11-25',
          capabilities: { tools: {} },
          serverInfo: { name: 'mcptrace-validation', version: '1.0.0' },
        });
        return;
      }
      if (dotnetMode === 'legacy' || dotnetMode === 'modern') {
        if (body.method === 'notifications/initialized') {
          res.writeHead(202).end();
        } else if (body.method === 'tools/list') {
          reply(res, body.id, {
            ...(dotnetMode === 'modern' ? { resultType: 'complete' } : {}),
            tools: [{ name: 'echo_marker', inputSchema: { type: 'object' } }],
          }, dotnetMode === 'modern');
        } else if (body.method === 'tools/call') {
          reply(res, body.id, {
            ...(dotnetMode === 'modern' ? { resultType: 'complete' } : {}),
            content: [{ type: 'text', text: body.params.arguments.marker }],
          }, dotnetMode === 'modern');
        } else {
          res.writeHead(400).end('unsupported method');
        }
        return;
      }
      const sessionId = req.headers['mcp-session-id'];
      let transport = sessions.get(sessionId);
      if (!transport && isInitializeRequest(body)) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => sessions.set(id, transport),
        });
        const server = createServer();
        transport.onclose = () => sessions.delete(transport.sessionId);
        await server.connect(transport);
      }
      if (!transport) {
        res.writeHead(400).end('unknown session');
        return;
      }
      const chunks = [];
      const write = res.write.bind(res);
      const end = res.end.bind(res);
      res.write = (chunk, ...args) => {
        if (chunk) chunks.push(Buffer.from(chunk));
        return write(chunk, ...args);
      };
      res.end = (chunk, ...args) => {
        if (chunk) chunks.push(Buffer.from(chunk));
        if (chunks.length) logBody('server-to-client', Buffer.concat(chunks));
        return end(chunk, ...args);
      };
      await transport.handleRequest(req, res, body);
    } catch (error) {
      console.error(error);
      if (!res.headersSent) res.writeHead(500).end(String(error));
    }
  });
  web.listen(port, '127.0.0.1', () => {
    fs.writeFileSync(`${workdir}/server-ready.json`, JSON.stringify({ pid: process.pid, port }));
  });
  const stop = setInterval(() => {
    if (fs.existsSync(`${workdir}/server-stop`)) {
      clearInterval(stop);
      web.close();
    }
  }, 100);
}

async function client() {
  if (!marker) throw new Error('client requires marker');
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
  const client = new Client({ name: 'mcptrace-node-validation', version: '1.0.0' });
  await client.connect(transport);
  const tools = await client.listTools();
  if (!tools.tools.some((tool) => tool.name === 'echo_marker')) throw new Error('missing tool');
  for (let i = 0; i < 4; i++) {
    const expected = `${marker}-${i}`;
    const result = await client.callTool({ name: 'echo_marker', arguments: { marker: expected } });
    if (result.isError || result.content[0]?.text !== expected) throw new Error('tool mismatch');
  }
  fs.writeFileSync(`${workdir}/client-ready.json`, JSON.stringify({ pid: process.pid, marker }));
  while (!fs.existsSync(`${workdir}/client-stop`)) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  await client.close();
}

await (role === 'server' ? serve() : client());
