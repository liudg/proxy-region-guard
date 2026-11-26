import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';

function argumentValue(argv: readonly string[], prefix: string): string {
  return argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length).trim().replace(/^"+|"+$/g, '') || '';
}

export function recordUpdateBootEvent(phase: string, message: string, argv: readonly string[] = process.argv): void {
  const file = argumentValue(argv, '--update-diagnostic-file=');
  if (!file) return;
  fs.appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), phase, message, pid: process.pid })}\n`, 'utf8');
}

export function writeUpdateReadyFile(argv: readonly string[]): void {
  const file = argumentValue(argv, '--update-ready-file=');
  if (!file) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporaryFile = `${file}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporaryFile, `${process.pid}:${Date.now()}\n`, { encoding: 'utf8', flag: 'wx' });
    fs.renameSync(temporaryFile, file);
  } finally {
    fs.rmSync(temporaryFile, { force: true });
  }
}

export function readUpdateFailureReason(argv: readonly string[]): string {
  const file = argumentValue(argv, '--update-diagnostic-file=');
  if (!file) return '';
  try {
    const records = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as { phase: string; message: string });
    const failure = records.find((record) => ['boot-failed', 'launch-failed', 'apply-failed', 'boot-exit', 'boot-timeout'].includes(record.phase));
    return failure ? `；原因：${failure.message}；诊断文件：${file}` : `；诊断文件：${file}`;
  } catch (error) {
    return `；诊断文件读取或解析失败：${error instanceof Error ? error.message : String(error)}；诊断文件：${file}`;
  }
}
