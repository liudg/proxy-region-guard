import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const release = JSON.parse(fs.readFileSync(path.join(root, 'resources/mihomo-release.json'), 'utf8'));
const directory = path.join(root, 'resources/mihomo');
const archive = path.join(directory, `mihomo-${release.version}.zip`);
const hash = (file) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
fs.mkdirSync(directory, { recursive: true });
const executable = path.join(directory, 'guard-mihomo.exe');
const manifestPath = path.join(directory, 'manifest.json');
if (fs.existsSync(executable) && fs.existsSync(manifestPath)) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.version === release.version && manifest.sha256 === hash(executable)) {
    console.log(`Mihomo ${release.version} 文件校验完成`);
    process.exit(0);
  }
}
if (!fs.existsSync(archive) || hash(archive) !== release.archiveSha256) {
  const response = await fetch(release.archiveUrl);
  if (!response.ok) throw new Error(`下载 Mihomo 失败：HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (createHash('sha256').update(bytes).digest('hex') !== release.archiveSha256) throw new Error('Mihomo 下载文件校验失败');
  fs.writeFileSync(archive, bytes);
}
const extracted = path.join(directory, 'extracted');
execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
  'Expand-Archive -LiteralPath $env:GUARD_CORE_ARCHIVE -DestinationPath $env:GUARD_CORE_EXTRACT -Force'],
{ windowsHide: true, env: { ...process.env, GUARD_CORE_ARCHIVE: archive, GUARD_CORE_EXTRACT: extracted } });
const executables = fs.readdirSync(extracted).filter((file) => file.endsWith('.exe'));
if (executables.length !== 1) throw new Error('Mihomo 压缩包必须包含唯一内核程序');
fs.copyFileSync(path.join(extracted, executables[0]), executable);
fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify({ version: release.version, sha256: hash(executable) }, null, 2));
console.log(`Mihomo ${release.version} 文件校验完成`);
