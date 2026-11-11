/** Content-Length framed LSP initialize control, exchanged over a real TCP socket. */
import fs from 'node:fs';
import net from 'node:net';

const workdir = process.argv[2];
if (!workdir) throw new Error('usage: node lsp_control.mjs WORKDIR');
const request = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: {
    processId: process.pid, clientInfo: { name: 'lsp-control', version: '1.0' },
    capabilities: {}, rootUri: 'file:///tmp/mcptrace-lsp-control', workspaceFolders: [],
  },
};
const response = { jsonrpc: '2.0', id: 1, result: { capabilities: { textDocumentSync: 1 } } };

function frame(message) {
  const body = Buffer.from(JSON.stringify(message));
  return Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]);
}
function log(direction, message) {
  fs.appendFileSync(`${workdir}/lsp-traffic.jsonl`,
    JSON.stringify({ direction, framing: 'content-length', message }) + '\n');
}
function consume(socket, onMessage) {
  let pending = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    for (;;) {
      const separator = pending.indexOf('\r\n\r\n');
      if (separator < 0) break;
      const header = pending.subarray(0, separator).toString('ascii');
      const length = Number(/^Content-Length: (\d+)$/m.exec(header)?.[1]);
      if (!Number.isInteger(length) || pending.length < separator + 4 + length) break;
      const body = pending.subarray(separator + 4, separator + 4 + length);
      pending = pending.subarray(separator + 4 + length);
      onMessage(JSON.parse(body.toString('utf8')));
    }
  });
}

const server = net.createServer((socket) => {
  consume(socket, (message) => {
    log('client-to-server', message);
    socket.write(frame(response));
  });
});
server.listen(0, '127.0.0.1', () => {
  const client = net.connect(server.address().port, '127.0.0.1');
  consume(client, (message) => {
    if (message.id !== request.id) throw new Error('response mismatch');
    log('server-to-client', message);
    fs.writeFileSync(`${workdir}/client-ready.json`, JSON.stringify({ pid: process.pid }));
  });
  client.on('connect', () => client.write(frame(request)));
  const stop = setInterval(() => {
    if (fs.existsSync(`${workdir}/client-stop`)) {
      clearInterval(stop);
      client.end();
      server.close();
    }
  }, 100);
});
