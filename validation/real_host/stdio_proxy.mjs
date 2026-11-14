/** Independent byte journal for a real MCP host's stdio connection. */
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';

const [logPath, serverPath] = process.argv.slice(2);
if (!logPath || !serverPath) throw new Error('usage: node stdio_proxy.mjs LOG SERVER');
const log = fs.openSync(logPath, 'wx');
const server = spawn(process.execPath, [serverPath], { stdio: ['pipe', 'pipe', 'inherit'] });

function record(direction, payload) {
  fs.writeSync(log, JSON.stringify({
    direction,
    observed_ns: Number(process.hrtime.bigint()),
    raw_base64: payload.toString('base64'),
    raw_sha256: createHash('sha256').update(payload).digest('hex'),
    message: JSON.parse(payload.toString('utf8')),
  }) + '\n');
}

function forward(source, destination, direction, interceptDiscovery = false) {
  let pending = Buffer.alloc(0);
  source.on('data', (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    for (;;) {
      const end = pending.indexOf(10);
      if (end < 0) break;
      const payload = pending.subarray(0, end);
      pending = pending.subarray(end + 1);
      if (payload.length === 0) continue;
      record(direction, payload);
      if (interceptDiscovery && JSON.parse(payload.toString('utf8')).method === 'server/discover') {
        const request = JSON.parse(payload.toString('utf8'));
        const response = Buffer.from(JSON.stringify({
          jsonrpc: '2.0', id: request.id,
          error: { code: -32601, message: 'Method not found' },
        }));
        record('server-to-client', response);
        process.stdout.write(Buffer.concat([response, Buffer.from('\n')]));
      } else {
        destination.write(Buffer.concat([payload, Buffer.from('\n')]));
      }
    }
  });
  source.on('end', () => destination.end());
}

forward(process.stdin, server.stdin, 'client-to-server', true);
forward(server.stdout, process.stdout, 'server-to-client');
server.on('exit', (code) => { fs.closeSync(log); process.exit(code ?? 0); });
