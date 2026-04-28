# Contributing

Thanks for taking a look. A few notes on how this package is shaped.

## Repository relationship

Until publish, the four packages live side-by-side in a local
`am-semnat-sdk/` checkout:

```
am-semnat-sdk/
├── ios/             # AmSemnatSDK podspec
├── android/         # ro.amsemnat:am-semnat-sdk
├── expo/            # @amsemnat/expo-sdk
└── verifier/        # this package
```

Each subdir is its own git repo with its own publish channel. The
verifier ships independently to npm as `@amsemnat/verifier`.

## Public API is frozen

The public surface (`src/index.ts` exports — `verifyPassive`,
`verifyPadesSignatures`, and the input/output types) mirrors the spec
for the four sibling SDKs. Top-level result fields (`valid`, `errors`,
`signerCommonName`, `signedAt`) match the mobile `verifyPassiveOffline`
shape. Don't add fields, rename options, or reorder enum values without
updating the iOS / Android / Expo siblings in lockstep. 0.x versions
move together.

## Building

```bash
npm install
npm run build        # src/ → dist/
npm test             # vitest — fixtures synthesized at test runtime
npm run lint         # tsc --noEmit
```

Tests have no external dependencies; the fixture generator builds
synthetic CSCA + DSC + SOD bundles and synthetic CEI PKI + signed PDFs
on demand using `node-forge` + `pkijs` + `pdf-lib`.

## What not to do

- **Don't bundle trust material.** The package ships with zero MAI
  certificates; consumers fetch the current CSCA / DGEP anchors from the
  official MAI publication points themselves. Bundling would turn this
  package into a trust-distribution channel, which is exactly what we
  decided against in the SDK design.
- **Don't add identity parsing.** This package verifies; it does not
  parse. DG1 MRZ extraction lives in `readIdentity` on the mobile side.
- **Don't loosen the `signingCertificateV2` binding check.** PAdES B-B
  requires it; without it an attacker can swap the embedded signer cert
  and pkijs's default CMS verify still passes.

## Reporting issues

File against whichever repo the bug lives in:

- API surface / cross-platform semantics → `am-semnat-sdk` meta repo
- Verifier behaviour or false positives/negatives → `am-semnat-verifier`
- Mobile read/sign behaviour → `am-semnat-ios-sdk` / `am-semnat-android-sdk`
