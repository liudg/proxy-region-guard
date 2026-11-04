import { execFile } from 'node:child_process';
import * as os from 'node:os';

export interface SystemProxyState {
  enabled: boolean;
  proxyUrl: string | null; // e.g., "http://127.0.0.1:7890" or "socks5h://127.0.0.1:1080"
  rawServer: string | null;
}

const REG_PATH = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

export function readWindowsSystemProxy(): Promise<SystemProxyState> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve({ enabled: false, proxyUrl: null, rawServer: null });
      return;
    }

    execFile(
      'reg.exe',
      ['query', REG_PATH],
      { windowsHide: true, timeout: 2500 },
      (err, stdout) => {
        if (err || !stdout) {
          resolve({ enabled: false, proxyUrl: null, rawServer: null });
          return;
        }

        let enabled = false;
        let rawServer: string | null = null;

        const lines = stdout.split(/\r?\n/);
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('ProxyEnable')) {
            const parts = trimmed.split(/\s+/);
            const val = parts[parts.length - 1];
            enabled = val === '0x1' || val === '1';
          } else if (trimmed.startsWith('ProxyServer')) {
            const match = trimmed.match(/^ProxyServer\s+REG_SZ\s+(.+)$/i);
            if (match && match[1]) {
              rawServer = match[1].trim();
            }
          }
        }

        if (!enabled || !rawServer) {
          resolve({ enabled: false, proxyUrl: null, rawServer });
          return;
        }

        const proxyUrl = normalizeProxyServerString(rawServer);
        resolve({ enabled: Boolean(proxyUrl), proxyUrl, rawServer });
      }
    );
  });
}

function normalizeProxyServerString(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;

  // 处理形如 "http=127.0.0.1:7890;https=127.0.0.1:7890;socks=127.0.0.1:7891"
  if (s.includes('=')) {
    const entries = s.split(';').map((part) => part.trim()).filter(Boolean);
    const map: Record<string, string> = {};
    for (const entry of entries) {
      const idx = entry.indexOf('=');
      if (idx > 0) {
        const k = entry.slice(0, idx).trim().toLowerCase();
        const v = entry.slice(idx + 1).trim();
        map[k] = v;
      }
    }
    const target = map['https'] || map['http'] || map['socks'] || Object.values(map)[0];
    if (!target) return null;
    if (map['socks'] && target === map['socks'] && !map['https'] && !map['http']) {
      return ensureScheme(target, 'socks5h');
    }
    return ensureScheme(target, 'http');
  }

  return ensureScheme(s, 'http');
}

function ensureScheme(addr: string, defaultScheme: 'http' | 'socks5h'): string {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(addr)) {
    if (addr.startsWith('socks5://')) {
      return addr.replace(/^socks5:\/\//, 'socks5h://');
    }
    return addr;
  }
  return `${defaultScheme}://${addr}`;
}

export function getNetworkInterfaceFingerprint(): string {
  try {
    const nets = os.networkInterfaces();
    const parts: string[] = [];
    for (const name of Object.keys(nets).sort()) {
      const list = nets[name] || [];
      for (const item of list) {
        if (!item.internal) {
          parts.push(`${name}:${item.family}:${item.address}`);
        }
      }
    }
    return parts.join('|');
  } catch {
    return '';
  }
}
