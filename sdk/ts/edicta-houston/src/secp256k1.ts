// SPDX-License-Identifier: Apache-2.0

// Public-key recovery on secp256k1, enough to tell which address signed a
// digest. It handles public data only (signatures, digests), so it makes no
// attempt at constant time; it never signs.

import { keccak256 } from "./keccak.js";

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
/** The group order. */
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const N = SECP256K1_N;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

/** Jacobian coordinates; z = 0 is the point at infinity. */
interface Jac {
  x: bigint;
  y: bigint;
  z: bigint;
}

const INF: Jac = { x: 0n, y: 1n, z: 0n };

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function pow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

// Both moduli are prime.
const inv = (a: bigint, m: bigint): bigint => pow(a, m - 2n, m);

function double(p: Jac): Jac {
  if (p.z === 0n || p.y === 0n) return INF;
  const a = (p.x * p.x) % P;
  const b = (p.y * p.y) % P;
  const c = (b * b) % P;
  const d = mod(2n * (mod((p.x + b) * (p.x + b), P) - a - c), P);
  const e = (3n * a) % P;
  const f = (e * e) % P;
  const x = mod(f - 2n * d, P);
  const y = mod(e * (d - x) - 8n * c, P);
  const z = (2n * p.y * p.z) % P;
  return { x, y, z };
}

function add(p: Jac, q: Jac): Jac {
  if (p.z === 0n) return q;
  if (q.z === 0n) return p;
  const pz2 = (p.z * p.z) % P;
  const qz2 = (q.z * q.z) % P;
  const u1 = (p.x * qz2) % P;
  const u2 = (q.x * pz2) % P;
  const s1 = (((p.y * qz2) % P) * q.z) % P;
  const s2 = (((q.y * pz2) % P) * p.z) % P;
  if (u1 === u2) return s1 === s2 ? double(p) : INF;
  const h = mod(u2 - u1, P);
  const r = mod(s2 - s1, P);
  const h2 = (h * h) % P;
  const h3 = (h2 * h) % P;
  const u1h2 = (u1 * h2) % P;
  const x = mod(r * r - h3 - 2n * u1h2, P);
  const y = mod(r * (u1h2 - x) - s1 * h3, P);
  const z = (((h * p.z) % P) * q.z) % P;
  return { x, y, z };
}

function mul(p: Jac, k: bigint): Jac {
  let r = INF;
  for (let i = BigInt(k.toString(2).length - 1); i >= 0n; i--) {
    r = double(r);
    if ((k >> i) & 1n) r = add(r, p);
  }
  return r;
}

function toBig(b: Uint8Array): bigint {
  return b.length === 0 ? 0n : BigInt("0x" + Buffer.from(b).toString("hex"));
}

function to32(v: bigint): Uint8Array {
  return new Uint8Array(Buffer.from(v.toString(16).padStart(64, "0"), "hex"));
}

/**
 * The address (20 bytes) whose key made the signature (r, s, yParity) over a
 * 32-byte digest, or undefined when no key did. r and s must lie in 1..n-1
 * and yParity be 0 or 1; whether a high s is acceptable is the caller's rule.
 */
export function recoverAddress(digest: Uint8Array, r: bigint, s: bigint, yParity: number): Uint8Array | undefined {
  if (digest.length !== 32 || r <= 0n || r >= N || s <= 0n || s >= N || (yParity !== 0 && yParity !== 1)) return undefined;
  const x = r;
  const alpha = mod(x * x * x + 7n, P);
  let y = pow(alpha, (P + 1n) / 4n, P);
  if ((y * y) % P !== alpha) return undefined;
  if (Number(y & 1n) !== yParity) y = P - y;
  const ri = inv(r, N);
  const e = mod(toBig(digest), N);
  const u1 = mod(-e * ri, N);
  const u2 = (s * ri) % N;
  const q = add(mul({ x: GX, y: GY, z: 1n }, u1), mul({ x, y, z: 1n }, u2));
  if (q.z === 0n) return undefined;
  const zi = inv(q.z, P);
  const zi2 = (zi * zi) % P;
  const qx = (q.x * zi2) % P;
  const qy = (((q.y * zi2) % P) * zi) % P;
  const pub = new Uint8Array(64);
  pub.set(to32(qx), 0);
  pub.set(to32(qy), 32);
  return keccak256(pub).subarray(12);
}

/** The digest personal_sign signs for a 32-byte message. */
export function personalDigest32(m: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
  const b = new Uint8Array(prefix.length + m.length);
  b.set(prefix, 0);
  b.set(m, prefix.length);
  return keccak256(b);
}
