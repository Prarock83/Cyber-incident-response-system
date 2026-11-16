'use strict';

/**
 * Generates the CIRS shield icons (16/32/48/128 px) as PNG files with no
 * external dependencies. Run from the repo root:
 *   node tools/generate-icons.js
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuffer, data]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([length, body, crc]);
}

function insideShield(x, y) {
  if (y < 0.07 || y > 0.95) return false;
  let half;
  if (y < 0.13) {
    half = 0.34 - (0.13 - y) * 1.6;
  } else if (y <= 0.5) {
    half = 0.34;
  } else {
    const t = (y - 0.5) / 0.45;
    half = 0.34 * Math.pow(1 - t, 0.75);
  }
  return Math.abs(x - 0.5) <= half;
}

function distanceToSegment(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSq = dx * dx + dy * dy;
  let t = lengthSq === 0 ? 0 : ((px - x1) * dx + (py - y1) * dy) / lengthSq;
  t = Math.max(0, Math.min(1, t));
  const cx = x1 + t * dx;
  const cy = y1 + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function insideCheck(x, y) {
  const a = distanceToSegment(x, y, 0.34, 0.51, 0.46, 0.64);
  const b = distanceToSegment(x, y, 0.46, 0.64, 0.69, 0.36);
  return Math.min(a, b) < 0.055;
}

function render(size) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  const scale = 4; // supersampling for smoother edges
  for (let y = 0; y < size; y += 1) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0; // filter byte: none
    for (let x = 0; x < size; x += 1) {
      let r = 0; let g = 0; let b = 0; let a = 0;
      for (let sy = 0; sy < scale; sy += 1) {
        for (let sx = 0; sx < scale; sx += 1) {
          const px = (x + (sx + 0.5) / scale) / size;
          const py = (y + (sy + 0.5) / scale) / size;
          if (!insideShield(px, py)) continue;
          const edge = !insideShield(px - 0.02, py) || !insideShield(px + 0.02, py)
            || !insideShield(px, py - 0.02) || !insideShield(px, py + 0.02);
          let cr; let cg; let cb;
          if (insideCheck(px, py)) {
            cr = 4; cg = 18; cb = 31;
          } else if (edge) {
            cr = 9; cg = 38; cb = 62;
          } else {
            const mix = Math.min(1, Math.max(0, (py - 0.1) / 0.85));
            cr = Math.round(34 + (37 - 34) * mix);
            cg = Math.round(211 + (99 - 211) * mix);
            cb = Math.round(238 + (235 - 238) * mix);
          }
          r += cr; g += cg; b += cb; a += 255;
        }
      }
      const samples = scale * scale;
      const offset = rowStart + 1 + x * 4;
      raw[offset] = Math.round(r / samples);
      raw[offset + 1] = Math.round(g / samples);
      raw[offset + 2] = Math.round(b / samples);
      raw[offset + 3] = Math.round(a / samples);
    }
  }

  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;   // bit depth
  header[9] = 6;   // colour type RGBA
  header[10] = 0;
  header[11] = 0;
  header[12] = 0;

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const outDir = path.join(__dirname, '..', 'extension', 'icons');
fs.mkdirSync(outDir, { recursive: true });
for (const size of [16, 32, 48, 128]) {
  const file = path.join(outDir, `icon${size}.png`);
  fs.writeFileSync(file, render(size));
  console.log(`wrote ${path.relative(process.cwd(), file)} (${size}x${size})`);
}
