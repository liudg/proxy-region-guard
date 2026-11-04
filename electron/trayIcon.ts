import { nativeImage, NativeImage } from 'electron';
import * as zlib from 'node:zlib';
import { GuardStatus } from '../src/shared/types';

interface RgbaColor {
  r: number;
  g: number;
  b: number;
}

const STATUS_PALETTE: Record<GuardStatus, { outer: RgbaColor; inner: RgbaColor }> = {
  ok: {
    outer: { r: 16, g: 185, b: 129 },   // Emerald #10B981
    inner: { r: 5, g: 150, b: 105 },    // #059669
  },
  mismatch: {
    outer: { r: 239, g: 68, b: 68 },    // Crimson Red #EF4444
    inner: { r: 220, g: 38, b: 38 },    // #DC2626
  },
  error: {
    outer: { r: 245, g: 158, b: 11 },   // Amber/Orange-Red #F59E0B
    inner: { r: 220, g: 38, b: 38 },    // #DC2626
  },
  unset: {
    outer: { r: 59, g: 130, b: 246 },   // Blue #3B82F6
    inner: { r: 37, g: 99, b: 235 },
  },
  checking: {
    outer: { r: 99, g: 102, b: 241 },   // Indigo #6366F1
    inner: { r: 79, g: 70, b: 229 },
  },
};

const iconCache = new Map<string, NativeImage>();

export function createStatusTrayIcon(status: GuardStatus, size = 32): NativeImage {
  const key = `tray:${status}:${size}`;
  const cached = iconCache.get(key);
  if (cached) return cached;

  const img = nativeImage.createEmpty();
  img.addRepresentation({
    scaleFactor: 1.0,
    width: 16,
    height: 16,
    buffer: renderStatusPngBuffer(status, 16),
  });
  img.addRepresentation({
    scaleFactor: 1.5,
    width: 24,
    height: 24,
    buffer: renderStatusPngBuffer(status, 24),
  });
  img.addRepresentation({
    scaleFactor: 2.0,
    width: 32,
    height: 32,
    buffer: renderStatusPngBuffer(status, 32),
  });

  iconCache.set(key, img);
  return img;
}

export function createWindowAppIcon(status: GuardStatus): NativeImage {
  const key = `win:${status}`;
  const cached = iconCache.get(key);
  if (cached) return cached;

  const img = nativeImage.createFromBuffer(renderStatusPngBuffer(status, 64));
  iconCache.set(key, img);
  return img;
}

export function renderStatusPngBuffer(status: GuardStatus, size: number): Buffer {

  const rgba = new Uint8Array(size * size * 4);
  const palette = STATUS_PALETTE[status];
  const cx = (size - 1) / 2;
  const cy = (size - 1) / 2;
  const maxR = size * 0.45;
  const ringR = size * 0.37;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist > maxR + 0.8) {
        rgba[idx + 3] = 0;
        continue;
      }

      // 抗锯齿外边缘
      const alpha = dist > maxR - 0.8 ? Math.max(0, Math.min(1, (maxR + 0.8 - dist) / 1.6)) : 1;

      const t = Math.min(1, dist / maxR);
      const baseColor = dist > ringR ? palette.outer : blendColor(palette.outer, palette.inner, t * 0.7);

      let r = baseColor.r;
      let g = baseColor.g;
      let b = baseColor.b;

      // 顶部轻微高光质感
      if (dy < 0 && dist < ringR) {
        const gloss = Math.max(0, (-dy / ringR) * 0.18);
        r = Math.min(255, Math.round(r + (255 - r) * gloss));
        g = Math.min(255, Math.round(g + (255 - g) * gloss));
        b = Math.min(255, Math.round(b + (255 - b) * gloss));
      }

      // 内部白色符号绘制（勾号 / 感叹号 / 圆点）
      const nx = (x - cx) / (size * 0.5); // -1 .. 1
      const ny = (y - cy) / (size * 0.5); // -1 .. 1
      const symbolCov = computeSymbolCoverage(status, nx, ny);

      if (symbolCov > 0) {
        r = Math.round(r * (1 - symbolCov) + 255 * symbolCov);
        g = Math.round(g * (1 - symbolCov) + 255 * symbolCov);
        b = Math.round(b * (1 - symbolCov) + 255 * symbolCov);
      }

      rgba[idx] = r;
      rgba[idx + 1] = g;
      rgba[idx + 2] = b;
      rgba[idx + 3] = Math.round(alpha * 255);
    }
  }

  return encodeRgbaToPng(size, size, rgba);
}

function blendColor(a: RgbaColor, b: RgbaColor, t: number): RgbaColor {
  return {
    r: Math.round(a.r + (b.r - a.r) * t),
    g: Math.round(a.g + (b.g - a.g) * t),
    b: Math.round(a.b + (b.b - a.b) * t),
  };
}

function distToSegment(
  px: number,
  py: number,
  x1: number,
  y1: number,
  x2: number,
  y2: number
): number {
  const l2 = (x2 - x1) ** 2 + (y2 - y1) ** 2;
  if (l2 === 0) return Math.hypot(px - x1, py - y1);
  let t = ((px - x1) * (x2 - x1) + (py - y1) * (y2 - y1)) / l2;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * (x2 - x1)), py - (y1 + t * (y2 - y1)));
}

function computeSymbolCoverage(status: GuardStatus, nx: number, ny: number): number {
  const stroke = 0.125;
  const feather = 0.055;

  if (status === 'ok') {
    // 对勾符号 ✓
    const d1 = distToSegment(nx, ny, -0.34, 0.03, -0.08, 0.29);
    const d2 = distToSegment(nx, ny, -0.08, 0.29, 0.38, -0.24);
    const d = Math.min(d1, d2);
    return smoothCoverage(d, stroke, feather);
  }

  if (status === 'mismatch' || status === 'error') {
    // 醒目感叹号 !
    const dBar = distToSegment(nx, ny, 0, -0.38, 0, 0.08);
    const dDot = Math.hypot(nx, ny - 0.33);
    const d = Math.min(dBar, dDot - 0.02);
    return smoothCoverage(d, stroke, feather);
  }

  // unset / checking: 中心圆环守护点
  const dCenter = Math.hypot(nx, ny);
  return smoothCoverage(dCenter, 0.2, feather);
}

function smoothCoverage(dist: number, radius: number, feather: number): number {
  if (dist <= radius - feather) return 1;
  if (dist >= radius + feather) return 0;
  return (radius + feather - dist) / (2 * feather);
}

// 轻量纯内置 PNG 编码器
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makePngChunk(type: string, data: Buffer): Buffer {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const crcInput = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(crcInput), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function encodeRgbaToPng(width: number, height: number, rgba: Uint8Array): Buffer {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4 + 1;
  const rawData = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    rawData[y * stride] = 0; // filter type None
    Buffer.from(rgba.buffer, rgba.byteOffset + y * width * 4, width * 4).copy(
      rawData,
      y * stride + 1
    );
  }

  const compressed = zlib.deflateSync(rawData);

  return Buffer.concat([
    signature,
    makePngChunk('IHDR', ihdr),
    makePngChunk('IDAT', compressed),
    makePngChunk('IEND', Buffer.alloc(0)),
  ]);
}
