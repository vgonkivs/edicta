// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { keccak256 } from "../dist/src/index.js";
import { SECP256K1_N, personalDigest32, recoverAddress } from "../dist/src/secp256k1.js";

const vectors = new URL("../../../../spec/vectors/profiles/eden-escrow/", import.meta.url);
const vec = (n) => JSON.parse(readFileSync(new URL(n, vectors), "utf8"));
const signedVec = vec("signed.json");
const actionVec = vec("action.json");
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const big = (h) => BigInt("0x" + h);
const addr = (b) => (b === undefined ? undefined : "0x" + hex(b));

test("the group order is the vectors'", () => {
  assert.equal(SECP256K1_N.toString(16), signedVec.secp256k1_n_hex);
});

test("every signed vector recovers to its payer over its sighash", () => {
  const key = signedVec.keys.payer1;
  assert.equal("0x" + hex(keccak256(unhex(key.public_key_hex.slice(2))).subarray(12)), key.address, "the key's address");
  for (const c of signedVec.cases) {
    assert.equal(addr(recoverAddress(unhex(c.sighash_hex), big(c.r_hex), big(c.s_hex), Number(c.y_parity))), c.payer, c.id);
    const action = actionVec.cases.find((a) => a.id === c.action_ref);
    assert.equal(hex(keccak256(unhex(action.tx_hex))), c.sighash_hex, `${c.id}: the sighash is keccak256 of the committed tx`);
  }
});

// The vector key payer1, and a second key (sha256 of "edicta ts handoff test:
// another payer"), each personal_sign-ing two paymentIds; made with the Go
// signer code.
const PAYER1 = signedVec.keys.payer1.address;
const OTHER = "0xc657ba7f60ad6034ae6c733c51e6753ecffb5c1b";
const proofs = [
  [PAYER1, "e7b0fe0c168a34ec93cfca6752955af23bbe002de0d16d399f35ff910b160f35", "06ca9a1c1571faefad19ada013c4e64815e56913f23a1dabd32f4525395975cc46d97c6eb47610bfff455f9a232a57850e49413d55e4dc07fc7757fe1e1fc5481c"],
  [PAYER1, "00".repeat(32), "e7cf3dfb92d71dc67ccc212c2cc3de383ed668fd9ac2aa72726d944f9bd284ec48ef638ecc9e709f96130e3389221003446e393953f6a9091ae6c3c2a84433e91b"],
  [OTHER, "e7b0fe0c168a34ec93cfca6752955af23bbe002de0d16d399f35ff910b160f35", "6d08f19d561c897c48dab3e8740eadb7d43eb474a2ebd6c15407a0c498c745ee0bbd434a7ad61ae16769565735729277d04b32d48747de832dac1d83c3f326a21b"],
  [OTHER, "00".repeat(32), "87f643d19f8b3e738bc8ef596dad6a964b8eb1d3c0ddfc0da57ade6230f47b794a116f684f56ac7af195eeb9298ef4605e4978625472ab3746b8ed5fddce1b411c"],
];

test("personal_sign proofs recover to their key, and only over their paymentId", () => {
  for (const [who, pid, sig] of proofs) {
    const r = big(sig.slice(0, 64));
    const s = big(sig.slice(64, 128));
    const v = parseInt(sig.slice(128), 16) - 27;
    assert.equal(addr(recoverAddress(personalDigest32(unhex(pid)), r, s, v)), who, pid);
    const other = pid === "00".repeat(32) ? "11".repeat(32) : "00".repeat(32);
    assert.notEqual(addr(recoverAddress(personalDigest32(unhex(other)), r, s, v)), who, "another paymentId");
    assert.notEqual(addr(recoverAddress(personalDigest32(unhex(pid)), r, s, 1 - v)), who, "the other parity");
  }
});

test("out-of-range signatures recover nothing", () => {
  const c = signedVec.cases[0];
  const d = unhex(c.sighash_hex);
  const r = big(c.r_hex);
  const s = big(c.s_hex);
  for (const [name, args] of [
    ["r = 0", [d, 0n, s, 0]],
    ["r = n", [d, SECP256K1_N, s, 0]],
    ["s = 0", [d, r, 0n, 0]],
    ["s = n", [d, r, SECP256K1_N, 0]],
    ["parity 2", [d, r, s, 2]],
    ["a 31-byte digest", [d.subarray(1), r, s, 0]],
  ]) {
    assert.equal(recoverAddress(...args), undefined, name);
  }
  // 5 is no x coordinate on the curve: x^3 + 7 = 132 has no square root mod p.
  assert.equal(recoverAddress(d, 5n, s, 0), undefined, "r off the curve");
});
