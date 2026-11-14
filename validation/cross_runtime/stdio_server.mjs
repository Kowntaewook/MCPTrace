/** Official TypeScript SDK stdio server for real-host process-memory checks. */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({ name: 'mcptrace-real-host-control', version: '1.0.0' });
server.registerTool(
  'echo_marker',
  { description: 'Return a synthetic marker', inputSchema: { marker: z.string() } },
  async ({ marker }) => ({ content: [{ type: 'text', text: marker }] }),
);
await server.connect(new StdioServerTransport());
