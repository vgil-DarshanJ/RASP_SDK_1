// Builds a test certificate carrying an Android key attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17) with chosen boot-state values, and prints it
// as Base64 DER. Test fixtures only: the certificate is self-signed by an
// ad-hoc key, nothing like a real Keystore attestation chain.
//
//   node tools/make-attestation-fixture.js <locked:true|false> <bootState:0-3> <osPatchYYYYMM> [securityLevel=1]
//
// Needs openssl on PATH.
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const [lockedArg = "false", bootArg = "2", patchArg = "202608", levelArg = "1"] = process.argv.slice(2);

function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, content) => Buffer.concat([Buffer.from(tag), len(content.length), content]);
function int(v) {
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let b = Buffer.from(hex, "hex");
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv([0x02], b);
}
const enumerated = (v) => tlv([0x0a], Buffer.from([v]));
const octets = (b) => tlv([0x04], b);
const bool = (v) => tlv([0x01], Buffer.from([v ? 0xff : 0x00]));
const seq = (...items) => tlv([0x30], Buffer.concat(items));
// Context-specific, constructed, high tag number (e.g. [704] -> BF 85 40).
function explicit(tagNumber, inner) {
  const digits = [];
  let n = tagNumber;
  digits.unshift(n & 0x7f);
  n >>= 7;
  while (n > 0) { digits.unshift(0x80 | (n & 0x7f)); n >>= 7; }
  return tlv([0xbf, ...digits], inner);
}

const rootOfTrust = seq(octets(Buffer.alloc(32, 7)), bool(lockedArg === "true"), enumerated(Number(bootArg)), octets(Buffer.alloc(32, 9)));
const hardwareEnforced = seq(explicit(704, rootOfTrust), explicit(706, int(Number(patchArg))), explicit(718, int(Number(patchArg) * 100 + 5)));
const keyDescription = seq(
  int(4), enumerated(Number(levelArg)), int(41), enumerated(Number(levelArg)),
  octets(Buffer.from("challenge")), octets(Buffer.alloc(0)),
  seq(), hardwareEnforced,
);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "att-"));
try {
  fs.writeFileSync(path.join(dir, "ext.cnf"),
    "[req]\ndistinguished_name=dn\n[dn]\n[ext]\n1.3.6.1.4.1.11129.2.1.17=DER:" + keyDescription.toString("hex") + "\n");
  execFileSync("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path.join(dir, "k.pem")]);
  execFileSync("openssl", ["req", "-new", "-x509", "-key", path.join(dir, "k.pem"), "-subj", "/CN=Android Keystore Key",
    "-days", "36500", "-config", path.join(dir, "ext.cnf"), "-extensions", "ext",
    "-outform", "DER", "-out", path.join(dir, "c.der")], { env: { ...process.env, MSYS_NO_PATHCONV: "1" } });
  process.stdout.write(fs.readFileSync(path.join(dir, "c.der")).toString("base64") + "\n");
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
