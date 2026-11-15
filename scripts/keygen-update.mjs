import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const keysDir = path.join(rootDir, '.keys');
const privateKeyPath = path.join(keysDir, 'update-signing-private.key');
const publicKeyPath = path.join(keysDir, 'update-signing-public.key');
const manifestTsPath = path.join(rootDir, 'src', 'shared', 'updateManifest.ts');

const force = process.argv.includes('--force');

if (fs.existsSync(privateKeyPath) && !force) {
  console.error(
    `⚠️ 私钥文件已存在: ${privateKeyPath}\n如需重新生成并覆盖现有密钥对，请执行: npm run keygen -- --force`
  );
  process.exit(1);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privateDerB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const publicDerB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

// 自检签名与验签闭环
const testMessage = Buffer.from('proxy-region-guard-keygen-selftest', 'utf-8');
const sig = crypto.sign(null, testMessage, privateKey);
const verified = crypto.verify(
  null,
  testMessage,
  crypto.createPublicKey({ key: Buffer.from(publicDerB64, 'base64'), format: 'der', type: 'spki' }),
  sig
);
if (!verified) {
  throw new Error('Ed25519 密钥对自检验签失败');
}

fs.mkdirSync(keysDir, { recursive: true });
fs.writeFileSync(privateKeyPath, `${privateDerB64}\n`, { encoding: 'utf-8' });
fs.writeFileSync(publicKeyPath, `${publicDerB64}\n`, { encoding: 'utf-8' });

if (fs.existsSync(manifestTsPath)) {
  const src = fs.readFileSync(manifestTsPath, 'utf-8');
  const pattern =
    /(export const BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64 =\s*')[^']*(';)/;
  if (!pattern.test(src)) {
    throw new Error(`未在 ${manifestTsPath} 中找到 BUILTIN_UPDATE_PUBLIC_KEY_SPKI_B64 常量`);
  }
  const updated = src.replace(pattern, `$1${publicDerB64}$2`);
  fs.writeFileSync(manifestTsPath, updated, 'utf-8');
}

console.log('✅ Ed25519 更新签名密钥对已生成并完成自检！');
console.log(`🔑 公钥 (已自动写入 src/shared/updateManifest.ts):\n   ${publicDerB64}`);
console.log(`🔒 私钥文件 (已被 .gitignore 忽略，切勿提交至代码库):\n   ${privateKeyPath}`);
console.log(
  '\n📌 GitHub Actions 配置指引:\n' +
    '   打开仓库 Settings -> Secrets and variables -> Actions -> New repository secret\n' +
    '   Name 填写: UPDATE_SIGNING_PRIVATE_KEY\n' +
    '   Secret 粘贴上述 update-signing-private.key 文件中的单行 Base64 字符串即可。'
);
