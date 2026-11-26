import * as dgram from 'node:dgram';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { NodeSnapshot, SubscriptionCatalog } from '../../electron/clash';
import { listen } from './testHarness';

export interface VlessTargetRecord {
  atyp: number;
  addr: string;
  port: number;
}

export interface Ipv4VlessTestRig {
  dnsPort: number;
  dnsQueries: Array<{ name: string; qtype: number }>;
  plainHostHeaders: string[];
  vlessTargets: VlessTargetRecord[];
  vergeDir: string;
  vlessSnap: NodeSnapshot;
  state: {
    traceReplyIp: string;
    ipv6OriginHits: number;
    onDnsQuery: ((qname: string, qtype: number) => Promise<void> | void) | null;
    onTraceRequest: (() => Promise<void> | void) | null;
  };
  cleanup: () => Promise<void>;
}

function encodeDnsName(name: string): Buffer {
  return Buffer.concat([
    ...name
      .split('.')
      .filter(Boolean)
      .map((label) =>
        Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')])
      ),
    Buffer.from([0]),
  ]);
}

function buildDnsReply(query: Buffer, qname: string, qtype: number): Buffer {
  let off = 12;
  while (query[off] !== 0) off += query[off] + 1;
  const qEnd = off + 5;
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  if (qname === 'v6only.claude.test') {
    if (qtype === 28) {
      header.writeUInt16BE(1, 6);
      const aaaa = Buffer.from([
        0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16,
        0x26, 0x07, 0x6b, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
      ]);
      return Buffer.concat([header, query.subarray(12, qEnd), aaaa]);
    }
    header.writeUInt16BE(0, 6);
    return Buffer.concat([header, query.subarray(12, qEnd)]);
  }
  if (qname === 'cname.claude.test' && qtype === 1) {
    header.writeUInt16BE(2, 6);
    const target = encodeDnsName('target.claude.test');
    const cnameAns = Buffer.concat([
      Buffer.from([0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 120]),
      Buffer.from([(target.length >> 8) & 0xff, target.length & 0xff]),
      target,
    ]);
    const aAns = Buffer.concat([
      target,
      Buffer.from([0, 1, 0, 1, 0, 0, 0, 90, 0, 4, 198, 51, 100, 42]),
    ]);
    return Buffer.concat([header, query.subarray(12, qEnd), cnameAns, aAns]);
  }
  if (qtype === 1) {
    header.writeUInt16BE(1, 6);
    const aAns = Buffer.from([
      0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 160, 79, 104, 10,
    ]);
    return Buffer.concat([header, query.subarray(12, qEnd), aAns]);
  }
  if (qtype === 28) {
    header.writeUInt16BE(1, 6);
    const aaaa = Buffer.from([
      0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16,
      0x26, 0x07, 0x6b, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]);
    return Buffer.concat([header, query.subarray(12, qEnd), aaaa]);
  }
  header.writeUInt16BE(0, 6);
  return Buffer.concat([header, query.subarray(12, qEnd)]);
}

export async function createIpv4VlessTestRig(
  ipv4Root: string,
  tlsCert: string,
  tlsKey: string,
  expectedIpv4Exit: string
): Promise<Ipv4VlessTestRig> {
  const state: Ipv4VlessTestRig['state'] = {
    traceReplyIp: expectedIpv4Exit,
    ipv6OriginHits: 0,
    onDnsQuery: null,
    onTraceRequest: null,
  };
  const dnsQueries: Array<{ name: string; qtype: number }> = [];
  const dnsServer = dgram.createSocket('udp4');
  dnsServer.on('message', (msg, rinfo) => {
    let off = 12;
    const labels: string[] = [];
    while (msg[off] !== 0 && off < msg.length) {
      labels.push(msg.subarray(off + 1, off + 1 + msg[off]).toString('ascii'));
      off += msg[off] + 1;
    }
    const qname = labels.join('.').toLowerCase();
    const qtype = msg.readUInt16BE(off + 1);
    dnsQueries.push({ name: qname, qtype });
    void Promise.resolve(state.onDnsQuery?.(qname, qtype))
      .catch(() => undefined)
      .then(() => {
        try {
          dnsServer.send(buildDnsReply(msg, qname, qtype), rinfo.port, rinfo.address);
        } catch {
          // socket closed during cleanup
        }
      });
  });
  await new Promise<void>((resolve) => dnsServer.bind(0, '127.0.0.1', resolve));
  const dnsPort = dnsServer.address().port;
  const plainHostHeaders: string[] = [];

  const tlsOrigin = https.createServer({ key: tlsKey, cert: tlsCert }, (req, res) => {
    const pathname = new URL(req.url || '/', 'https://127.0.0.1').pathname;
    void Promise.resolve(state.onTraceRequest?.())
      .catch(() => undefined)
      .then(() => {
        if (res.destroyed) return;
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        if (pathname === '/cdn-cgi/trace') {
          res.end(
            `fl=1f1\nh=${req.headers.host || 'claude.ai'}\nip=${
              state.traceReplyIp
            }\nloc=JP\n`
          );
          return;
        }
        res.end(`${expectedIpv4Exit}\n`);
      });
  });

  const plainOrigin = http.createServer((req, res) => {
    plainHostHeaders.push(String(req.headers.host || ''));
    if (req.method === 'POST' && req.url === '/echo') {
      const bodyChunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => bodyChunks.push(chunk));
      req.on('end', () => {
        const body = Buffer.concat(bodyChunks);
        res.writeHead(200, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Content-Length': String(body.length),
        });
        res.end(body);
      });
      return;
    }
    const okBody = 'plain-http-ipv4-ok';
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Length': String(Buffer.byteLength(okBody)),
    });
    res.end(okBody);
  });

  const ipv6Origin = http.createServer((_req, res) => {
    state.ipv6OriginHits++;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ipv6-only-origin-ok');
  });

  const [tlsOriginPort, plainOriginPort, ipv6OriginPort] = await Promise.all([
    listen(tlsOrigin, '127.0.0.1'),
    listen(plainOrigin, '127.0.0.1'),
    listen(ipv6Origin, '::1'),
  ]);

  const vlessTargets: VlessTargetRecord[] = [];
  const vlessSockets = new Set<net.Socket>();
  const vlessServer = net.createServer((client) => {
    vlessSockets.add(client);
    let up: net.Socket | null = null;
    const headerChunks: Buffer[] = [];
    let headerLen = 0;

    const onHeaderData = (chunk: Buffer) => {
      try {
        headerChunks.push(chunk);
        headerLen += chunk.length;
        if (headerLen < 18) return;
        const buf =
          headerChunks.length === 1
            ? headerChunks[0]
            : Buffer.concat(headerChunks);
        const addonLen = buf[17];
        const off = 18 + addonLen;
        if (buf.length < off + 4) return;
        const dstPort = buf.readUInt16BE(off + 1);
        const atyp = buf[off + 3];
        let requiredLen = 0;
        if (atyp === 1) {
          requiredLen = off + 8;
        } else if (atyp === 2) {
          if (buf.length < off + 5) return;
          requiredLen = off + 5 + buf[off + 4];
        } else if (atyp === 3) {
          requiredLen = off + 20;
        } else {
          client.destroy();
          return;
        }
        if (buf.length < requiredLen) return;

        client.pause();
        client.removeListener('data', onHeaderData);
        let addr = '';
        if (atyp === 1) {
          addr = [...buf.subarray(off + 4, off + 8)].join('.');
        } else if (atyp === 2) {
          const len = buf[off + 4];
          addr = buf.subarray(off + 5, off + 5 + len).toString('utf8');
        } else {
          const segs: string[] = [];
          for (let i = 0; i < 16; i += 2) {
            segs.push(buf.readUInt16BE(off + 4 + i).toString(16));
          }
          addr = segs.join(':');
        }
        vlessTargets.push({ atyp, addr, port: dstPort });
        const remainder = buf.subarray(requiredLen);
        const routeToIpv6 =
          atyp === 3 || (atyp === 2 && addr.toLowerCase() === 'v6only.claude.test');
        const targetLocalPort = routeToIpv6
          ? ipv6OriginPort
          : dstPort === 80
          ? plainOriginPort
          : tlsOriginPort;
        up = routeToIpv6
          ? net.connect({ host: '::1', port: targetLocalPort, family: 6 }, () => {
              client.write(Buffer.from([0, 0]));
              if (remainder.length > 0) up!.write(remainder);
              client.pipe(up!);
              up!.pipe(client);
            })
          : net.connect(targetLocalPort, '127.0.0.1', () => {
              client.write(Buffer.from([0, 0]));
              if (remainder.length > 0) up!.write(remainder);
              client.pipe(up!);
              up!.pipe(client);
            });
        up.on('error', () => client.destroy());
      } catch {
        client.destroy();
      }
    };

    client.on('data', onHeaderData);
    client.on('error', () => up?.destroy());
    client.once('close', () => {
      client.removeListener('data', onHeaderData);
      up?.destroy();
      vlessSockets.delete(client);
    });
  });
  const vlessPort = await listen(vlessServer, '127.0.0.1');

  const vergeDir = path.join(ipv4Root, 'verge');
  fs.mkdirSync(path.join(vergeDir, 'profiles'), { recursive: true });
  fs.writeFileSync(
    path.join(vergeDir, 'profiles.yaml'),
    yaml.dump({
      current: 'vless-prof',
      items: [
        {
          uid: 'vless-prof',
          name: 'VLESS IPv4 测试订阅',
          type: 'local',
          file: 'vless.yaml',
        },
      ],
    }),
    'utf8'
  );
  fs.writeFileSync(
    path.join(vergeDir, 'profiles', 'vless.yaml'),
    yaml.dump({
      proxies: [
        {
          name: '双栈VLESS测试节点',
          type: 'vless',
          server: '127.0.0.1',
          port: vlessPort,
          uuid: '11111111-1111-1111-1111-111111111111',
          tls: false,
        },
      ],
    }),
    'utf8'
  );
  const cat = new SubscriptionCatalog(vergeDir);
  cat.refresh();
  const vlessSnap = cat.capture('vless-prof', '双栈VLESS测试节点');

  const cleanup = async () => {
    for (const sock of vlessSockets) sock.destroy();
    await Promise.all([
      new Promise<void>((resolve) => vlessServer.close(() => resolve())),
      new Promise<void>((resolve) => tlsOrigin.close(() => resolve())),
      new Promise<void>((resolve) => plainOrigin.close(() => resolve())),
      new Promise<void>((resolve) => ipv6Origin.close(() => resolve())),
      new Promise<void>((resolve) => dnsServer.close(() => resolve())),
    ]);
  };

  return {
    dnsPort,
    dnsQueries,
    plainHostHeaders,
    vlessTargets,
    vergeDir,
    vlessSnap,
    state,
    cleanup,
  };
}
