// Creates Ed25519 keys and signs malware-reputation lists for the
// `malware_reputation` detector (RaspMalwareReputationProbes).
//
//   node tools/sign-reputation-list.js keygen <out-dir>
//       writes <out-dir>/reputation-signing-key.pem (PRIVATE — keep it offline)
//       and prints the public key (Base64 SPKI) to put in
//       RaspLeanConfig.malwareReputationPublicKey
//
//   node tools/sign-reputation-list.js sign <payload.json> <private-key.pem> > reputation-list.json
//       payload.json: {"version": <integer>, "entries": [{"package": "...", "category": "...", "severity": "..."}]}
//       The payload text is signed byte-for-byte as it is in the file.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const [command, a, b] = process.argv.slice(2);

if (command === "keygen" && a) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  fs.mkdirSync(a, { recursive: true });
  const keyPath = path.join(a, "reputation-signing-key.pem");
  fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  console.error(`private key written to ${keyPath}`);
  console.log(publicKey.export({ type: "spki", format: "der" }).toString("base64"));
} else if (command === "sign" && a && b) {
  const payload = fs.readFileSync(a, "utf8").trim();
  const parsed = JSON.parse(payload); // refuse to sign something the SDK cannot read
  if (!Number.isInteger(parsed.version) || !Array.isArray(parsed.entries)) {
    throw new Error("payload needs an integer 'version' and an 'entries' array");
  }
  const key = crypto.createPrivateKey(fs.readFileSync(b));
  const signature = crypto.sign(null, Buffer.from(payload, "utf8"), key).toString("base64");
  console.log(JSON.stringify({ payload, signature }, null, 2));
} else {
  console.error("usage: keygen <out-dir> | sign <payload.json> <private-key.pem>");
  process.exit(2);
}
