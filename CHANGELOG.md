# Changelog

All notable changes to `@amsemnat/verifier-node` are documented in this file.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers ship in lockstep with the sibling SDKs
(`am-semnat-ios-sdk`, `am-semnat-android-sdk`, `@amsemnat/expo-sdk`)
through the 0.x cycle.

## 0.1.0 — Unreleased

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
- Strict ETSI EN 319 122 `signingCertificateV2` binding check for PAdES
  signatures — the embedded signer cert must match the cert hash signed
  into the attribute. Without this check an attacker who swaps the
  embedded cert still passes pkijs's default CMS verify.

### Out of scope for 0.1.0

- Timestamp tokens (PAdES B-T). `signedAt` comes from the `signingTime`
  signed attribute only.
- CRL / OCSP / LTV. Freshness and revocation are the consumer's
  responsibility, matching the SDK's stated trust-material posture.
- MRZ / DG1 parsing. Identity extraction is `readIdentity`'s job on the
  mobile SDKs.
- PEM trust anchors. DER only in 0.1.0.
