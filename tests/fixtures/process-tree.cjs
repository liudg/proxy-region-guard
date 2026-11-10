const { spawn } = require('node:child_process');
const { writeFileSync } = require('node:fs');

const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
  windowsHide: true,
  stdio: 'ignore',
});
child.once('error', (error) => { throw error; });
child.once('spawn', () => writeFileSync(process.argv[2], JSON.stringify({ pid: child.pid })));
setInterval(() => {}, 1000);
