import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function runGit(args) {
  try {
    return execFileSync('git', args, {
      cwd: rootDir,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return '';
  }
}

function getArgValue(flag) {
  const idx = process.argv.indexOf(flag);
  if (idx >= 0 && idx + 1 < process.argv.length) {
    return process.argv[idx + 1];
  }
  return '';
}

function parseSemverTag(raw) {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.trim().replace(/^v/i, '');
  const m =
    /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.exec(cleaned);
  if (!m) return null;
  if (
    !/^(0|[1-9]\d*)$/.test(m[1]) ||
    !/^(0|[1-9]\d*)$/.test(m[2]) ||
    !/^(0|[1-9]\d*)$/.test(m[3])
  ) {
    return null;
  }
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  if (
    !Number.isSafeInteger(major) ||
    !Number.isSafeInteger(minor) ||
    !Number.isSafeInteger(patch)
  ) {
    return null;
  }
  let prerelease = [];
  if (m[4] !== undefined) {
    const parts = m[4].split('.');
    for (const part of parts) {
      if (!part || !/^[0-9A-Za-z-]+$/.test(part)) return null;
      if (/^\d+$/.test(part) && part.length > 1 && part.startsWith('0')) return null;
    }
    prerelease = parts;
  }
  return { major, minor, patch, prerelease };
}

function compareSemverTag(tagA, tagB) {
  const pa = parseSemverTag(tagA);
  const pb = parseSemverTag(tagB);
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;

  if (pa.major !== pb.major) return pa.major > pb.major ? 1 : -1;
  if (pa.minor !== pb.minor) return pa.minor > pb.minor ? 1 : -1;
  if (pa.patch !== pb.patch) return pa.patch > pb.patch ? 1 : -1;

  // SemVer 2.0 规范：正式版 > 同主次修订的预发布版 (如 1.1.0 > 1.1.0-beta.1)
  if (pa.prerelease.length === 0 && pb.prerelease.length === 0) return 0;
  if (pa.prerelease.length === 0) return 1;
  if (pb.prerelease.length === 0) return -1;

  const len = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < len; i++) {
    const idA = pa.prerelease[i];
    const idB = pb.prerelease[i];
    if (idA === undefined) return -1;
    if (idB === undefined) return 1;
    if (idA === idB) continue;
    const numA = /^\d+$/.test(idA) ? Number(idA) : null;
    const numB = /^\d+$/.test(idB) ? Number(idB) : null;
    if (numA !== null && numB !== null) return numA > numB ? 1 : -1;
    if (numA !== null) return -1;
    if (numB !== null) return 1;
    return idA > idB ? 1 : -1;
  }
  return 0;
}

const currentTag =
  getArgValue('--tag') || runGit(['describe', '--tags', '--exact-match', 'HEAD']);
const outPath = getArgValue('--out') || path.join(rootDir, 'release', 'release-notes.md');

// 优先选取当前 HEAD 可达的祖先版本标签，并按严格 SemVer 2.0 降序排列（确保 1.1.0 > 1.1.0-beta.1）
const mergedRaw = runGit(['-c', 'versionsort.suffix=-', 'tag', '--list', 'v*', '--merged', 'HEAD']);
const fallbackRaw = mergedRaw || runGit(['-c', 'versionsort.suffix=-', 'tag', '--list', 'v*']);

const sortedSemverTags = fallbackRaw
  .split(/\r?\n/)
  .map((s) => s.trim())
  .filter((s) => Boolean(s) && parseSemverTag(s) !== null)
  .sort((a, b) => compareSemverTag(b, a));

let prevTag = '';
if (currentTag && parseSemverTag(currentTag)) {
  const olderTag = sortedSemverTags.find(
    (t) => t !== currentTag && compareSemverTag(t, currentTag) < 0
  );
  if (olderTag) {
    prevTag = olderTag;
  }
} else if (sortedSemverTags.length > 0) {
  prevTag = sortedSemverTags[0];
}

const range = prevTag ? `${prevTag}..HEAD` : 'HEAD';
const rawCommits = prevTag
  ? runGit(['log', range, '--no-merges', '--pretty=format:%s (%h)'])
  : runGit(['log', '-n', '20', '--no-merges', '--pretty=format:%s (%h)']);

const lines = rawCommits
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => l && !/^chore\(release\):/i.test(l));

const feats = [];
const fixes = [];
const others = [];

for (const line of lines) {
  if (/^feat(\(.+?\))?[!:]\s*/i.test(line)) {
    feats.push(line.replace(/^feat(\(.+?\))?[!:]\s*/i, ''));
  } else if (/^fix(\(.+?\))?[!:]\s*/i.test(line)) {
    fixes.push(line.replace(/^fix(\(.+?\))?[!:]\s*/i, ''));
  } else {
    others.push(line);
  }
}

const sections = [];
if (feats.length > 0) {
  sections.push('### ✨ 新增特性\n' + feats.map((s) => `- ${s}`).join('\n'));
}
if (fixes.length > 0) {
  sections.push('### 🐛 问题修复与优化\n' + fixes.map((s) => `- ${s}`).join('\n'));
}
if (others.length > 0) {
  sections.push('### 🔧 其他变更\n' + others.map((s) => `- ${s}`).join('\n'));
}
if (sections.length === 0) {
  sections.push('- 常规稳定性维护与离线 GeoIP 数据库同步更新');
}

const notes = sections.join('\n\n') + '\n';
fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
fs.writeFileSync(path.resolve(outPath), notes, 'utf-8');
console.log(`📝 已生成版本更新说明 (基准: ${prevTag || '初始版本'}) -> ${outPath}`);
