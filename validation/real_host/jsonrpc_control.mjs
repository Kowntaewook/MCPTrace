/** Non-MCP JSON-RPC client/server exchanged over a real TCP socket. */
import fs from 'node:fs';
import net from 'node:net';
import { createHash } from 'node:crypto';

const workdir = process.argv[2];
if (!workdir) throw new Error('usage: node jsonrpc_control.mjs WORKDIR');
const request = { jsonrpc: '2.0', id: 7, method: 'account/query', params: { account: 'synthetic-control' } };
const response = { jsonrpc: '2.0', id: 7, result: { status: 'ok', source: 'non-mcp-control' } };

function line(message) { return Buffer.from(JSON.stringify(message) + '\n'); }
function log(direction, payload) {
  fs.appendFileSync(`${workdir}/traffic.jsonl`, JSON.stringify({
    direction,
    raw_base64: payload.toString('base64'),
    raw_sha256: createHash('sha256').update(payload).digest('hex'),
    message: JSON.parse(payload.toString('utf8')),
  }) + '\n');
}
function consume(socket, direction, onMessage) {
  let pending = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    for (;;) {
      const end = pending.indexOf(10);
      if (end < 0) break;
      const payload = pending.subarray(0, end);
      pending = pending.subarray(end + 1);
      log(direction, payload);
      onMessage(JSON.parse(payload.toString('utf8')));
    }
  });
}

const server = net.createServer((socket) => {
  consume(socket, 'client-to-server', () => socket.write(line(response)));
});
server.listen(0, '127.0.0.1', () => {
  const client = net.connect(server.address().port, '127.0.0.1');
  consume(client, 'server-to-client', (message) => {
    if (message.id !== request.id) throw new Error('response mismatch');
    fs.writeFileSync(`${workdir}/client-ready.json`, JSON.stringify({ pid: process.pid }));
  });
  client.on('connect', () => client.write(line(request)));
  const stop = setInterval(() => {
    if (fs.existsSync(`${workdir}/client-stop`)) {
      clearInterval(stop);
      client.end();
      server.close();
    }
  }, 100);
});
