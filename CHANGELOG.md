# Changelog

All notable changes to `@amsemnat/verifier` are documented in this file.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers ship in lockstep with the sibling SDKs
(`am-semnat-ios-sdk`, `am-semnat-android-sdk`, `@amsemnat/expo-sdk`)
through the 0.x cycle.

## 0.1.2 — 2026-04-27

### Changed

- **Renamed package** from `@amsemnat/verifier-node` to `@amsemnat/verifier`.
  The old name shipped before the WebCrypto migration in 0.1.1, when the
  package really was Node-only; now that the same `dist/` runs unchanged in
  browsers, edge runtimes, Deno, and Bun, the `-node` suffix is misleading.
  Source code, public API, and `dist/` contents are byte-identical to
  `@amsemnat/verifier-node@0.1.1`. Migrate via:

  ```bash
  npm uninstall @amsemnat/verifier-node
  npm install @amsemnat/verifier
  ```

  …and replace `from "@amsemnat/verifier-node"` with `from "@amsemnat/verifier"`
  in your imports. `@amsemnat/verifier-node@0.1.1` is deprecated on npm with a
  pointer to this package and remains installable indefinitely.

## 0.1.1 — 2026-04-27

### Changed

- Internal hashing migrated from `node:crypto` to WebCrypto
  (`globalThis.crypto.subtle.digest`), and `timingSafeEqual` replaced with
  a portable constant-time JS comparison. The package now runs unchanged
  in Node 20+, modern browsers, Cloudflare Workers, Deno, and Bun.
- Public API is unchanged. `verifyPassive` and `verifyPadesSignatures`
  remain async; only internal helpers were migrated.

### Removed

- SHA-224 dropped from the supported hash algorithm set. WebCrypto does
  not implement it, and Romanian CEI artifacts in the wild use SHA-256 —
  no observed consumer impact. SHA-1, SHA-256, SHA-384, and SHA-512 stay
  supported.

## 0.1.0 — 2026-04-27

Initial release.

### Added

- `verifyPassive(input)` — eMRTD passive authentication. Verifies the
  SOD CMS signature, validates the DSC chain against caller-supplied
  CSCA anchors, and re-computes per-DG hashes against the SOD's signed
  values.
- `verifyPadesSignatures(input)` — verifies every PAdES B-B signature in
  an assembled signed PDF. Returns one result per signature in document
  order with `coversWholeDocument`, `signatureIndex`, and `fieldName`
  for multi-sig disambiguation.
- Top-level result shape (`valid`, `errors`, `signerCommonName`,
  `signedAt`) and trust-anchor format (flat DER list, auto-classified by
  self-signedness) match the mobile SDKs' `verifyPassiveOffline` for
  cross-platform parity.
- `PassiveVerificationResult` additionally surfaces granular outcome
  flags (`signatureValid`, `certificateValid`, `hashesValid`) and a
  per-DG breakdown (`dataGroupResults`). Server-side dogfooding showed
  consumers want to attribute failure to a specific stage (chain vs.
  signature vs. hash) when surfacing `/auth/verify` errors; the rolled-up
  `valid` alone wasn't enough.
- Strict ETSI EN 319 122 `signingCertificateV2` binding check for PAdES
  signatures — the embedded signer cert must match the cert hash signed
  into the attribute. Without this check an attacker who swaps the
  embedded cert still passes pkijs's default CMS verify.
- `verifyPassive` checks only the DGs the caller supplies. SOD-listed
  DGs not in the input are not flagged — Romanian CEI cards include
  DG3/DG7 hashes the mobile SDK never reads, so requiring all of them
  would force consumers to read every data group whether they need it
  or not. A provided DG missing from the SOD IS flagged (suggests
  caller's bytes are mislabeled).

### Out of scope for 0.1.0

- Timestamp tokens (PAdES B-T). `signedAt` comes from the `signingTime`
  signed attribute only.
- CRL / OCSP / LTV. Freshness and revocation are the consumer's
  responsibility, matching the SDK's stated trust-material posture.
- MRZ / DG1 parsing. Identity extraction is `readIdentity`'s job on the
  mobile SDKs.
- PEM trust anchors. DER only in 0.1.0.
