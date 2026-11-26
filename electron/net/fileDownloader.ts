import * as crypto from 'node:crypto';
import type * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as path from 'node:path';
import { getRawFs } from '../utils/rawFs';
import {
  MAX_HEADER_BYTES,
  normalizeProxyUrlScheme,
  REDIRECT_STATUS_CODES,
  resolveSafeRedirectUrl,
} from './proxyUrl';
import { createOneShotAgent, timeoutMsOrBudget } from './scopedProxyAgents';

const rawFs = getRawFs();

export interface DownloadFileOptions {
  targetUrl: string;
  proxyUrl: string | null;
  destFilePath: string;
  timeoutMs: number;
  stallTimeoutMs?: number;
  maxBytes?: number;
  redirectsLeft?: number;
  allowLocalhost?: boolean;
  deadlineAt?: number;
  onProgress?: (downloadedBytes: number, totalBytes: number | null) => void;
}

export async function downloadFileViaProxy(
  options: DownloadFileOptions
): Promise<{ size: number; sha256: string }> {
  const {
    targetUrl,
    proxyUrl,
    destFilePath,
    timeoutMs,
    stallTimeoutMs = 20000,
    maxBytes = 512 * 1024 * 1024,
    redirectsLeft = 6,
    allowLocalhost = false,
    onProgress,
  } = options;

  const deadlineAt = options.deadlineAt ?? Date.now() + timeoutMs;

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    throw new Error(`下载 URL 格式无效: ${targetUrl}`);
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error(`不支持的下载 URL 协议: ${parsedUrl.protocol}`);
  }

  const budgetMs = deadlineAt - Date.now();
  if (budgetMs <= 0) {
    throw new Error('下载总时长超出上限');
  }

  await rawFs.promises.mkdir(path.dirname(destFilePath), { recursive: true });

  const normalizedProxy = proxyUrl ? normalizeProxyUrlScheme(proxyUrl) : null;
  const effectiveStallMs = Math.min(stallTimeoutMs, budgetMs);

  return new Promise<{ size: number; sha256: string }>((resolve, reject) => {
    let settled = false;
    let req: http.ClientRequest | null = null;
    let agent: http.Agent | null = null;
    let fileStream: fs.WriteStream | null = null;
    let stallTimer: NodeJS.Timeout | null = null;

    const cleanupTransport = () => {
      try {
        agent?.destroy();
      } catch {
        // ignore
      }
    };

    const clearStall = () => {
      if (stallTimer) {
        clearTimeout(stallTimer);
        stallTimer = null;
      }
    };

    const armStall = () => {
      clearStall();
      stallTimer = setTimeout(() => {
        req?.destroy(new Error('下载连接停滞超时'));
        finish(new Error('下载连接停滞超时'));
      }, effectiveStallMs);
    };

    const cleanupPartialFile = () => {
      const ws = fileStream;
      fileStream = null;
      const removeBestEffort = () => {
        try {
          if (rawFs.existsSync(destFilePath)) {
            rawFs.rmSync(destFilePath, { force: true });
          }
        } catch {
          // ignore
        }
      };
      if (ws) {
        ws.once('close', removeBestEffort);
        try {
          ws.destroy();
        } catch {
          removeBestEffort();
        }
      } else {
        removeBestEffort();
      }
    };

    const finish = (err: Error | null, result?: { size: number; sha256: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardDeadline);
      clearStall();
      if (err) {
        req?.destroy();
      }
      cleanupTransport();
      if (err) {
        cleanupPartialFile();
        reject(err);
      } else if (result) {
        resolve(result);
      }
    };

    const hardDeadline = setTimeout(() => {
      req?.destroy(new Error('下载总时长超出上限'));
      finish(new Error('下载总时长超出上限'));
    }, budgetMs);

    armStall();

    const isHttps = parsedUrl.protocol === 'https:';
    const baseHeaders: Record<string, string> = {
      'User-Agent': 'ProxyRegionGuard-Updater/1.0',
      Accept: 'application/octet-stream, */*',
      'Cache-Control': 'no-cache',
      Connection: 'close',
    };

    const handleResponse = (res: http.IncomingMessage) => {
      res.on('error', (err) => {
        finish(err);
      });

      armStall();
      const code = res.statusCode || 0;

      if (REDIRECT_STATUS_CODES.has(code) && res.headers.location && redirectsLeft > 0) {
        if (settled) return;
        settled = true;
        clearTimeout(hardDeadline);
        clearStall();
        const locationHeader = res.headers.location;
        res.destroy();
        cleanupTransport();

        let nextUrl: string;
        try {
          nextUrl = resolveSafeRedirectUrl(parsedUrl, locationHeader, allowLocalhost);
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
          return;
        }

        const remainingMs = deadlineAt - Date.now();
        if (remainingMs <= 0) {
          reject(new Error('下载总时长超出上限'));
          return;
        }

        downloadFileViaProxy({
          ...options,
          targetUrl: nextUrl,
          proxyUrl: normalizedProxy,
          timeoutMs: remainingMs,
          deadlineAt,
          redirectsLeft: redirectsLeft - 1,
        })
          .then(resolve)
          .catch(reject);
        return;
      }

      if (code < 200 || code >= 300) {
        res.destroy();
        finish(new Error(`下载返回异常 HTTP 状态码 ${code}`));
        return;
      }

      const contentLengthHeader = res.headers['content-length'];
      const rawTotal = contentLengthHeader ? Number(contentLengthHeader) : NaN;
      const totalBytes = Number.isFinite(rawTotal) && rawTotal > 0 ? rawTotal : null;
      if (totalBytes !== null && totalBytes > maxBytes) {
        res.destroy();
        req?.destroy();
        finish(new Error('下载文件体积超出安全上限'));
        return;
      }

      const hash = crypto.createHash('sha256');
      let downloadedBytes = 0;
      fileStream = rawFs.createWriteStream(destFilePath, { flags: 'w' });

      fileStream.on('error', (err) => {
        res.destroy();
        req?.destroy();
        finish(err);
      });

      res.on('data', (chunk: Buffer | string) => {
        if (settled) return;
        armStall();
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        downloadedBytes += buf.length;
        if (downloadedBytes > maxBytes) {
          res.destroy();
          req?.destroy();
          finish(new Error('下载文件体积超出安全上限'));
          return;
        }
        hash.update(buf);
        if (fileStream && !fileStream.write(buf)) {
          res.pause();
          fileStream.once('drain', () => {
            if (!settled) res.resume();
          });
        }
        onProgress?.(downloadedBytes, totalBytes);
      });

      res.on('end', () => {
        if (settled) return;
        if (totalBytes !== null && downloadedBytes !== totalBytes) {
          finish(new Error(`下载文件不完整 (${downloadedBytes}/${totalBytes} 字节)`));
          return;
        }
        const ws = fileStream;
        fileStream = null;
        if (!ws) {
          finish(new Error('文件写入流意外关闭'));
          return;
        }
        const digest = hash.digest('hex').toLowerCase();
        ws.once('error', (err) => finish(err));
        ws.once('close', () => {
          finish(null, {
            size: downloadedBytes,
            sha256: digest,
          });
        });
        ws.end();
      });
    };

    try {
      if (normalizedProxy && !normalizedProxy.toLowerCase().startsWith('socks') && !isHttps) {
        const proxyParsed = new URL(normalizedProxy);
        agent =
          proxyParsed.protocol === 'https:'
            ? new https.Agent({ keepAlive: false, timeout: effectiveStallMs })
            : new http.Agent({ keepAlive: false, timeout: timeoutMsOrBudget(effectiveStallMs) });
        const headers: Record<string, string> = {
          ...baseHeaders,
          Host: parsedUrl.host,
        };
        if (proxyParsed.username || proxyParsed.password) {
          const auth = Buffer.from(
            `${decodeURIComponent(proxyParsed.username)}:${decodeURIComponent(proxyParsed.password)}`
          ).toString('base64');
          headers['Proxy-Authorization'] = `Basic ${auth}`;
        }
        const proxyTransport = proxyParsed.protocol === 'https:' ? https : http;
        req = proxyTransport.request(
          {
            hostname: proxyParsed.hostname.replace(/^\[|\]$/g, ''),
            port: proxyParsed.port || (proxyParsed.protocol === 'https:' ? 443 : 80),
            method: 'GET',
            path: parsedUrl.toString(),
            agent,
            timeout: effectiveStallMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers,
          },
          handleResponse
        );
      } else {
        agent = createOneShotAgent(normalizedProxy, isHttps, effectiveStallMs);

        const transport = isHttps ? https : http;
        req = transport.request(
          parsedUrl,
          {
            method: 'GET',
            agent,
            timeout: effectiveStallMs,
            maxHeaderSize: MAX_HEADER_BYTES,
            headers: baseHeaders,
          },
          handleResponse
        );
      }

      req.on('timeout', () => {
        req?.destroy(new Error('下载套接字读取超时'));
      });

      req.on('error', (err) => {
        finish(err);
      });

      req.end();
    } catch (err) {
      finish(err instanceof Error ? err : new Error(String(err)));
    }
  });
}
