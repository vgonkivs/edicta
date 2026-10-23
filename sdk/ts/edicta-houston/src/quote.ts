// SPDX-License-Identifier: Apache-2.0

// The payment server's PAYMENT-REQUIRED quote, read as the escrow profile
// reads it: the header decoding, the strict JSON document rules, and the
// selection of the escrow-upto entry by paymentId. JSON.parse is not used:
// it keeps the last of two repeated member names and accepts lone
// surrogates, so two readers could see two different quotes.

export const MAX_REQUIREMENTS = 16384;
// The longest base64 value that can decode to MAX_REQUIREMENTS bytes.
const MAX_HEADER_CHARS = 21848;
const MAX_DEPTH = 16;

export const SCHEME = "escrow-upto";

/**
 * Decodes a PAYMENT-REQUIRED header value: the standard base64 alphabet, at
 * most two "=" at the end (then a length that is a multiple of 4), and a
 * decoded document of 1 to 16384 bytes. Returns undefined for anything else.
 */
export function decodePaymentRequired(value: string): Uint8Array | undefined {
  if (value.length > MAX_HEADER_CHARS) return undefined;
  const body = value.replace(/=+$/, "");
  const pad = value.length - body.length;
  if (pad > 2 || (pad > 0 && value.length % 4 !== 0)) return undefined;
  if (!/^[A-Za-z0-9+/]*$/.test(body) || body.length % 4 === 1) return undefined;
  // The alphabet check runs first: Buffer would skip unknown characters.
  const r = new Uint8Array(Buffer.from(body, "base64"));
  if (r.length < 1 || r.length > MAX_REQUIREMENTS) return undefined;
  return r;
}

type JsonValue =
  | { kind: "object"; members: Map<string, JsonValue> }
  | { kind: "array"; elems: JsonValue[] }
  | { kind: "string"; text: string }
  | { kind: "number"; text: string }
  | { kind: "literal"; text: string };

class JsonError extends Error {}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Parses exactly one strict JSON document: valid UTF-8, whitespace only
 * space, tab, LF and CR, no member name twice in one object at any depth
 * (compared after unescaping), no raw control character or unpaired
 * surrogate in a string, containers nested at most 16 deep, nothing after
 * the value. Throws on anything else.
 */
export function parseStrictJSON(b: Uint8Array): JsonValue {
  let text: string;
  try {
    text = utf8.decode(b);
  } catch {
    throw new JsonError("not UTF-8");
  }
  let off = 0;
  const space = () => {
    while (off < text.length && (text[off] === " " || text[off] === "\t" || text[off] === "\n" || text[off] === "\r")) off++;
  };
  const hex4 = (): number => {
    const h = text.slice(off, off + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(h)) throw new JsonError("bad \\u escape");
    off += 4;
    return parseInt(h, 16);
  };
  const str = (): string => {
    off++;
    let out = "";
    for (;;) {
      if (off >= text.length) throw new JsonError("unterminated string");
      const c = text.charCodeAt(off);
      if (c === 0x22) {
        off++;
        return out;
      }
      if (c < 0x20) throw new JsonError("raw control character");
      if (c !== 0x5c) {
        out += text[off];
        off++;
        continue;
      }
      off++;
      const e = text[off];
      off++;
      switch (e) {
        case '"':
        case "\\":
        case "/":
          out += e;
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const hi = hex4();
          if (hi >= 0xdc00 && hi <= 0xdfff) throw new JsonError("unpaired surrogate");
          if (hi >= 0xd800 && hi <= 0xdbff) {
            if (text[off] !== "\\" || text[off + 1] !== "u") throw new JsonError("unpaired surrogate");
            off += 2;
            const lo = hex4();
            if (lo < 0xdc00 || lo > 0xdfff) throw new JsonError("unpaired surrogate");
            out += String.fromCharCode(hi, lo);
          } else {
            out += String.fromCharCode(hi);
          }
          break;
        }
        default:
          throw new JsonError("bad escape");
      }
    }
  };
  const num = (): JsonValue => {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(off));
    if (m === null) throw new JsonError("malformed number");
    off += m[0].length;
    return { kind: "number", text: m[0] };
  };
  const value = (depth: number): JsonValue => {
    space();
    if (off >= text.length) throw new JsonError("value expected");
    const c = text[off];
    if (c === "{" || c === "[") {
      if (depth >= MAX_DEPTH) throw new JsonError("nested too deep");
      off++;
      space();
      if (c === "[") {
        const elems: JsonValue[] = [];
        if (text[off] === "]") {
          off++;
          return { kind: "array", elems };
        }
        for (;;) {
          elems.push(value(depth + 1));
          space();
          if (text[off] === ",") {
            off++;
            continue;
          }
          if (text[off] === "]") {
            off++;
            return { kind: "array", elems };
          }
          throw new JsonError("bad array");
        }
      }
      const members = new Map<string, JsonValue>();
      if (text[off] === "}") {
        off++;
        return { kind: "object", members };
      }
      for (;;) {
        space();
        if (text[off] !== '"') throw new JsonError("member name expected");
        const name = str();
        if (members.has(name)) throw new JsonError("repeated member");
        space();
        if (text[off] !== ":") throw new JsonError("colon expected");
        off++;
        members.set(name, value(depth + 1));
        space();
        if (text[off] === ",") {
          off++;
          continue;
        }
        if (text[off] === "}") {
          off++;
          return { kind: "object", members };
        }
        throw new JsonError("bad object");
      }
    }
    if (c === '"') return { kind: "string", text: str() };
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return num();
    for (const lit of ["true", "false", "null"]) {
      if (text.startsWith(lit, off)) {
        off += lit.length;
        return { kind: "literal", text: lit };
      }
    }
    throw new JsonError("unexpected character");
  };
  const root = value(0);
  space();
  if (off !== text.length) throw new JsonError("data after the document");
  return root;
}

function member(v: JsonValue | undefined, name: string): JsonValue | undefined {
  return v?.kind === "object" ? v.members.get(name) : undefined;
}

function paymentIdOf(v: JsonValue | undefined): string | undefined {
  if (v?.kind !== "string" || !/^0x[0-9A-Fa-f]{64}$/.test(v.text)) return undefined;
  return v.text.slice(2).toLowerCase();
}

/**
 * True when R, a decoded PAYMENT-REQUIRED document, is a strict JSON object
 * with x402Version the token 2 and an accepts array, of which exactly one
 * element is an escrow-upto entry whose extra.paymentId is paymentIdHex (64
 * hex digits): the server asks again for that very payment. No other field
 * is read.
 */
export function asksForPayment(r: Uint8Array, paymentIdHex: string): boolean {
  if (r.length < 1 || r.length > MAX_REQUIREMENTS) return false;
  let doc: JsonValue;
  try {
    doc = parseStrictJSON(r);
  } catch {
    return false;
  }
  const version = member(doc, "x402Version");
  const accepts = member(doc, "accepts");
  if (doc.kind !== "object" || version?.kind !== "number" || version.text !== "2" || accepts?.kind !== "array") return false;
  const want = paymentIdHex.toLowerCase();
  let n = 0;
  for (const e of accepts.elems) {
    const scheme = member(e, "scheme");
    const extra = member(e, "extra");
    if (scheme?.kind !== "string" || scheme.text !== SCHEME || extra?.kind !== "object") continue;
    if (paymentIdOf(member(extra, "paymentId")) === want) n++;
  }
  return n === 1;
}
