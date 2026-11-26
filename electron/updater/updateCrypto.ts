import * as crypto from 'node:crypto';
import {
  buildUpdateSignaturePayload,
  BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64,
  UpdateReleaseManifest,
} from '../../src/shared/updateManifest';
import { getRawFs } from '../utils/rawFs';

export { getRawFs };

export function parseEd25519PrivateKey(rawKey: string): crypto.KeyObject {
  const trimmed = rawKey.trim();
  if (!trimmed) {
    throw new Error('Ed25519 私钥为空');
  }
  const keyObj = trimmed.includes('BEGIN PRIVATE KEY')
    ? crypto.createPrivateKey({ key: trimmed, format: 'pem' })
    : crypto.createPrivateKey({
        key: Buffer.from(trimmed.replace(/\s+/g, ''), 'base64'),
        format: 'der',
        type: 'pkcs8',
      });
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`不受支持的私钥算法 (${String(keyObj.asymmetricKeyType)})，必须为 ed25519`);
  }
  return keyObj;
}

export function parseEd25519PublicKey(rawKey: string): crypto.KeyObject {
  const trimmed = rawKey.trim();
  if (!trimmed) {
    throw new Error('Ed25519 公钥为空');
  }
  const keyObj = trimmed.includes('BEGIN PUBLIC KEY')
    ? crypto.createPublicKey({ key: trimmed, format: 'pem' })
    : crypto.createPublicKey({
        key: Buffer.from(trimmed.replace(/\s+/g, ''), 'base64'),
        format: 'der',
        type: 'spki',
      });
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`不受支持的公钥算法 (${String(keyObj.asymmetricKeyType)})，必须为 ed25519`);
  }
  return keyObj;
}

export function signUpdateManifest(
  manifestWithoutSig: Omit<UpdateReleaseManifest, 'signature'>,
  privateKeyText: string
): string {
  const privKey = parseEd25519PrivateKey(privateKeyText);
  const payload = Buffer.from(buildUpdateSignaturePayload(manifestWithoutSig), 'utf-8');
  return crypto.sign(null, payload, privKey).toString('base64');
}

export function verifyUpdateManifestSignature(
  manifest: UpdateReleaseManifest,
  publicKeyText: string = BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64
): boolean {
  if (!manifest.signature || typeof manifest.signature !== 'string') {
    return false;
  }
  const sigClean = manifest.signature.trim();
  if (!sigClean || !/^[A-Za-z0-9+/=]+$/.test(sigClean)) {
    return false;
  }

  try {
    const pubKey = parseEd25519PublicKey(publicKeyText);
    const sigBuf = Buffer.from(sigClean, 'base64');
    if (sigBuf.length !== 64) {
      return false;
    }
    const payload = Buffer.from(buildUpdateSignaturePayload(manifest), 'utf-8');
    return crypto.verify(null, payload, pubKey, sigBuf);
  } catch {
    return false;
  }
}

export async function computeFileSha256(
  filePath: string
): Promise<{ sha256: string; size: number }> {
  const rawFs = getRawFs();
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    let size = 0;
    const stream = rawFs.createReadStream(filePath);
    stream.on('data', (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buf.length;
      hash.update(buf);
    });
    stream.on('error', reject);
    stream.on('end', () => {
      resolve({ sha256: hash.digest('hex').toLowerCase(), size });
    });
  });
}

export async function validateAsarArchiveHeader(asarPath: string): Promise<void> {
  const rawFs = getRawFs();
  const fh = await rawFs.promises.open(asarPath, 'r');
  try {
    const stat = await fh.stat();
    if (stat.size < 32) {
      throw new Error('ASAR 包体积异常过小');
    }
    const headerBuf = Buffer.alloc(32);
    const { bytesRead } = await fh.read(headerBuf, 0, 32, 0);
    if (bytesRead < 26) {
      throw new Error('ASAR 包头部读取不完整');
    }
    const picklePayloadSize = headerBuf.readUInt32LE(0);
    const jsonLen = headerBuf.readUInt32LE(12);
    const jsonPrefix = headerBuf.subarray(16, 26).toString('utf-8');
    if (picklePayloadSize !== 4 || jsonLen < 10 || !jsonPrefix.startsWith('{"files":')) {
      throw new Error('文件不是合法的 Electron ASAR 归档结构');
    }
  } finally {
    await fh.close();
  }
}
