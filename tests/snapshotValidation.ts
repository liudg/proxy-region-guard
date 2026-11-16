import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import * as yaml from 'js-yaml';
import { SubscriptionCatalog } from '../electron/subscriptionCatalog';
import { verifyCore } from '../electron/privateKernel';
import { independentNodeDns } from '../electron/nodeDns';

export function validateSnapshots(root: string): void {
  const directory = path.join(root, 'snapshot-validation');
  fs.mkdirSync(path.join(directory, 'profiles'), { recursive: true });
  fs.writeFileSync(path.join(directory, 'profiles.yaml'), yaml.dump({ items: [{ uid: 'validation', type: 'local', file: 'nodes.yaml' }] }));
  const keys = generateKeyPairSync('x25519');
  const privateKey = keys.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('base64');
  const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  const nodes = [
    { name: 'WireGuard', type: 'wireguard', server: '192.0.2.1', port: 51820, ip: '10.0.0.2', 'private-key': privateKey, 'public-key': publicKey, udp: true },
    { name: 'DNS出口', type: 'direct' },
  ];
  const file = path.join(directory, 'profiles', 'nodes.yaml');
  fs.writeFileSync(file, yaml.dump({ proxies: nodes, dns: { 'proxy-server-nameserver': ['https://1.1.1.1/dns-query#DNS出口'] } }));
  const catalog = new SubscriptionCatalog(directory);
  catalog.refresh();
  const snapshot = catalog.capture('validation', 'WireGuard');
  assert.equal(snapshot.proxies[0]['private-key'], privateKey);
  assert.ok(snapshot.proxies.some((proxy) => proxy.name === 'DNS出口'));
  assert.deepEqual(snapshot.files, {});
  const configuration = path.join(directory, 'wireguard.yaml');
  fs.writeFileSync(configuration, yaml.dump({ proxies: snapshot.proxies, dns: { enable: true, nameserver: snapshot.dns['proxy-server-nameserver'] }, rules: ['MATCH,WireGuard'] }));
  execFileSync(verifyCore(path.resolve('resources/mihomo')), ['-t', '-d', directory, '-f', configuration], { windowsHide: true, stdio: 'pipe' });
  console.log('通过：WireGuard 真实密钥及 DNS 代理依赖由实际 Mihomo 校验');

  fs.writeFileSync(path.join(directory, 'clash-verge.yaml'), yaml.dump({ dns: { listen: '0.0.0.0:1053', nameserver: ['https://1.1.1.1/dns-query#DNS出口'] } }));
  fs.writeFileSync(file, yaml.dump({ proxies: nodes, dns: { 'proxy-server-nameserver': ['127.0.0.1:1053'] } }));
  catalog.refresh();
  const independent = catalog.capture('validation', 'WireGuard');
  assert.deepEqual(independent.dns['proxy-server-nameserver'], ['https://1.1.1.1/dns-query#DNS出口']);
  assert.ok(independent.proxies.some((proxy) => proxy.name === 'DNS出口'));
  fs.unlinkSync(path.join(directory, 'clash-verge.yaml'));
  assert.deepEqual(independent.dns['proxy-server-nameserver'], ['https://1.1.1.1/dns-query#DNS出口']);
  assert.throws(() => catalog.capture('validation', 'WireGuard'), /无法确定本机 DNS/);
  console.log('通过：保存本机 DNS 的明确上游，拒绝无法确定的本机转发依赖');
  assert.throws(() => independentNodeDns({ 'proxy-server-nameserver': ['127.0.0.2:1053'] },
    { listen: '127.0.0.1:1053', nameserver: ['8.8.8.8'] }), /无法确定本机 DNS/);
  assert.throws(() => independentNodeDns({ 'proxy-server-nameserver': ['https://127.0.0.1:1053/dns-query'] },
    { listen: '127.0.0.1:1053', nameserver: ['8.8.8.8'] }), /无法展开/);

  const install = path.join(root, 'clean-core-install');
  fs.mkdirSync(path.join(install, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(install, 'resources', 'mihomo'), { recursive: true });
  fs.copyFileSync('scripts/prepare-mihomo.mjs', path.join(install, 'scripts', 'prepare-mihomo.mjs'));
  fs.copyFileSync('resources/mihomo-release.json', path.join(install, 'resources', 'mihomo-release.json'));
  const release = JSON.parse(fs.readFileSync('resources/mihomo-release.json', 'utf8'));
  const archive = `mihomo-${release.version}.zip`;
  const cachedArchive = path.join('resources/mihomo', archive);
  if (fs.existsSync(cachedArchive)) fs.copyFileSync(cachedArchive, path.join(install, 'resources', 'mihomo', archive));
  for (let attempt = 0; attempt < 2; attempt++) {
    execFileSync(process.env.GUARD_TEST_NODE!, [path.join(install, 'scripts', 'prepare-mihomo.mjs')], { windowsHide: true, stdio: 'pipe' });
    assert.ok(fs.existsSync(verifyCore(path.join(install, 'resources', 'mihomo'))));
  }
  console.log('通过：空内核目录从官方压缩包准备文件，重复准备完成完整性检查');
}
