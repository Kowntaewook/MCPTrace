/* Load only in an isolated test host; a request file names the exact PID. */
const fs = require('node:fs');
const request = process.env.MCPTRACE_SNAPSHOT_REQUEST;
const addonPath = process.env.MCPTRACE_SNAPSHOT_ADDON;
if (request && addonPath) {
  const timer = setInterval(() => {
    if (!fs.existsSync(request)) return;
    const job = JSON.parse(fs.readFileSync(request, 'utf8'));
    if (job.pid !== process.pid) return;
    fs.unlinkSync(request);
    try {
      const summary = JSON.parse(require(addonPath).snapshot(job.output));
      fs.writeFileSync(`${job.output}.json`, JSON.stringify({ pid: process.pid, ...summary }) + '\n');
    } catch (error) {
      fs.writeFileSync(`${job.output}.error`, String(error) + '\n');
    }
  }, 200);
  timer.unref();
}
