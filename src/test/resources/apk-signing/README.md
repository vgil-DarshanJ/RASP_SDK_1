# APK signing-block fixtures

Signed with `apksigner` (build-tools 36.0.0) from a one-file zip, using
throwaway test keys that exist nowhere else. Used by `RaspApkSigningBlockTest`.

| File | Key | Schemes | Certificate SHA-256 |
|---|---|---|---|
| `rsa_v2v3.apk` | RSA 2048, `CN=RASP Test RSA` | v2, v3 | `7D1D7C9238B9935EFD87874B41D7131AE6058D167654C2C2791470655193C09C` |
| `ec_v2.apk` | EC P-256, `CN=RASP Test EC` | v2 | `ED729484B004A83B1622BC656BC374BB85DA79C0EB16E448F21D89660D57515A` |
| `attacker_v2v3.apk` | RSA 2048, `CN=RASP Test Attacker` | v2, v3 | `E7C44C89912F26543B92CA5476B1EDC829295CCF266E38BED1840382AD5C2DAA` |
| `rsa_v1only.apk` | RSA (as above) | v1 (JAR) only | — (no signing block) |

```
apksigner sign --ks <key>.p12 --min-sdk-version 24 \
  --v1-signing-enabled <b> --v2-signing-enabled <b> --v3-signing-enabled <b> \
  --out <name>.apk unsigned.apk
```
