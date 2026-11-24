import { build } from 'esbuild';
import { generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import electron from 'electron';

function generateSelfSignedTestCert(dnsNames, ipv4List) {
  const derLen = (n) => {
    if (n < 128) return Buffer.from([n]);
    const bytes = [];
    let v = n;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v >>= 8;
    }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  };
  const tag = (t, buf) => Buffer.concat([Buffer.from([t]), derLen(buf.length), buf]);
  const seq = (...parts) => tag(0x30, Buffer.concat(parts));
  const set = (...parts) => tag(0x31, Buffer.concat(parts));
  const oid = (s) => {
    const nums = s.split('.').map(Number);
    const out = [nums[0] * 40 + nums[1]];
    for (let i = 2; i < nums.length; i++) {
      let v = nums[i];
      const stack = [v & 0x7f];
      while ((v >>= 7) > 0) stack.unshift((v & 0x7f) | 0x80);
      out.push(...stack);
    }
    return tag(0x06, Buffer.from(out));
  };
  const asnInt = (value) => {
    let buf;
    if (typeof value === 'number') {
      const bytes = [];
      let v = value;
      do {
        bytes.unshift(v & 0xff);
        v >>= 8;
      } while (v > 0);
      buf = Buffer.from(bytes);
    } else {
      buf = value;
    }
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
    return tag(0x02, buf);
  };
  const bitStr = (buf, unusedBits = 0) => tag(0x03, Buffer.concat([Buffer.from([unusedBits]), buf]));
  const octStr = (buf) => tag(0x04, buf);
  const utf8 = (s) => tag(0x0c, Buffer.from(s, 'utf8'));
  const utc = (d) =>
    tag(0x17, Buffer.from(`${d.toISOString().replace(/[-:T]/g, '').slice(2, 14)}Z`, 'ascii'));

  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const alg = seq(oid('1.2.840.113549.1.1.11'), tag(0x05, Buffer.alloc(0)));
  const subject = seq(set(seq(oid('2.5.4.3'), utf8('ProxyRegionGuard Regression Test CA'))));
  const notBefore = new Date(Date.now() - 5 * 60_000);
  const notAfter = new Date(Date.now() + 24 * 60 * 60_000);
  const serial = randomBytes(8);
  serial[0] &= 0x7f;
  if (serial[0] === 0) serial[0] = 1;

  const sanEntries = [
    ...dnsNames.map((host) => tag(0x82, Buffer.from(host, 'ascii'))),
    ...ipv4List.map((ip) => tag(0x87, Buffer.from(ip.split('.').map(Number)))),
  ];
  const exts = tag(
    0xa3,
    seq(
      // BasicConstraints: CA:TRUE (critical)
      seq(oid('2.5.29.19'), tag(0x01, Buffer.from([0xff])), octStr(seq(tag(0x01, Buffer.from([0xff]))))),
      // KeyUsage: digitalSignature | keyEncipherment | keyCertSign (critical)
      seq(oid('2.5.29.15'), tag(0x01, Buffer.from([0xff])), octStr(bitStr(Buffer.from([0xa4]), 1))),
      // ExtendedKeyUsage: serverAuth
      seq(oid('2.5.29.37'), octStr(seq(oid('1.3.6.1.5.5.7.3.1')))),
      // SubjectAlternativeName
      seq(oid('2.5.29.17'), octStr(seq(...sanEntries)))
    )
  );
  const tbs = seq(
    tag(0xa0, asnInt(2)),
    asnInt(serial),
    alg,
    subject,
    seq(utc(notBefore), utc(notAfter)),
    subject,
    spki,
    exts
  );
  const signature = cryptoSign('sha256', tbs, privateKey);
  const certDer = seq(tbs, alg, bitStr(signature));
  const certPem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return { certPem, keyPem };
}

const directory = await mkdtemp(path.join(tmpdir(), 'guard-regression-'));
try {
  const entries = process.argv[2] ? [process.argv[2]] : ['tests/regression.ts', 'tests/proxyConsensus.ts', 'tests/appIdentity.ts', 'tests/claudeVerificationRecovery.ts', 'tests/updaterIntegration.ts'];
  const updaterApp = path.join(directory, 'updater-app.cjs');
  await build({ entryPoints: ['tests/updaterApp.ts'], outfile: updaterApp, bundle: true, platform: 'node', format: 'cjs', external: ['electron'] });
  const testTlsCertPath = path.join(directory, 'test-tls-ca.pem');
  const testTlsKeyPath = path.join(directory, 'test-tls-key.pem');
  if (entries.some((entry) => path.basename(entry) === 'proxyConsensus.ts')) {
    const { certPem, keyPem } = generateSelfSignedTestCert(
      [
        'claude.ai',
        'ipv4.icanhazip.com',
        'checkip.amazonaws.com',
        'api.ipify.org',
        'cp.cloudflare.com',
        'ident.me',
        'www.google.com',
        'www.youtube.com',
      ],
      ['127.0.0.1']
    );
    await Promise.all([
      writeFile(testTlsCertPath, certPem, 'utf8'),
      writeFile(testTlsKeyPath, keyPem, 'utf8'),
    ]);
  }
  for (const [index, entry] of entries.entries()) {
    const output = path.join(directory, `test-${index}.cjs`);
    await build({
      entryPoints: [entry],
      outfile: output,
      bundle: true,
      platform: 'node',
      target: 'node20',
      format: 'cjs',
      external: ['electron', 'original-fs'],
      banner: {
        js: `(() => { let fatal = false; const exitFail = () => { try { require('electron').app.exit(1); } catch { process.exit(1); } }; const fail = (type, tag, err) => { process.exitCode = 1; if (fatal) return; fatal = true; console.error(tag, err); if (process.listenerCount(type) > 1) { setTimeout(exitFail, 8000).unref(); return; } setImmediate(exitFail); }; process.on('uncaughtException', (err) => fail('uncaughtException', '[uncaughtException]', err)); process.on('unhandledRejection', (err) => fail('unhandledRejection', '[unhandledRejection]', err)); })();`,
      },
    });
    const isProxyConsensus = path.basename(entry) === 'proxyConsensus.ts';
    const env = {
      ...process.env,
      GUARD_TEST_NODE: process.execPath,
      GUARD_TEST_DATA: path.join(directory, `user-data-${index}`),
      GUARD_UPDATER_TEST_APP: updaterApp,
      ...(isProxyConsensus
        ? {
            NODE_EXTRA_CA_CERTS: testTlsCertPath,
            GUARD_TEST_TLS_CERT: testTlsCertPath,
            GUARD_TEST_TLS_KEY: testTlsKeyPath,
          }
        : {}),
    };
    delete env.ELECTRON_RUN_AS_NODE;
    const child = spawn(electron, [output], { stdio: 'inherit', env, windowsHide: true });
    process.exitCode = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => resolve(code ?? 1));
    });
    if (process.exitCode !== 0) break;
  }
} finally {
  if (path.dirname(path.resolve(directory)) !== path.resolve(tmpdir())) {
    throw new Error('测试临时目录超出预期范围');
  }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
