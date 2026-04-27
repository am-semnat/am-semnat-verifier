# `@amsemnat/verifier`

Verifier for Romanian eID artifacts produced by the
[am-semnat](https://amsemnat.ro) SDKs. Pure JavaScript, runs unchanged
in Node 20+, modern browsers, Cloudflare Workers, Deno, and Bun.

Two operations:

- **`verifyPassive`** — eMRTD passive authentication. Takes the raw
  `EF.SOD` bytes plus the data groups read from the chip and verifies
  the SOD CMS signature, the DSC chain to a caller-supplied
  CSCA Romania anchor, and the per-DG hashes. Use this server-side when
  you receive `RomanianIdentity.rawSod` / `RomanianIdentity.rawDg*` from
  one of the mobile SDKs.

- **`verifyPadesSignatures`** — verifies every PAdES B-B signature in
  an assembled signed PDF. Returns one result per signature in document
  order, with `coversWholeDocument` for incremental-update detection.

This package ships **zero MAI trust material**. Consumers fetch the
current CSCA Romania (DGP) and RO CEI MAI Root/Sub-CA (DGEP) certs
themselves from the official MAI publication points.

- **DGP — `CSCA Romania`**, published at
  <https://pasapoarte.mai.gov.ro/csca.html>. Self-signed ICAO CSCA that
  issues the Document Signer embedded in the eMRTD SOD. This is the
  trust anchor for `verifyPassive(...)`.
- **DGEP — `RO CEI MAI Root-CA` / `Sub-CA`**, published at
  <https://hub.mai.gov.ro/cei/info/descarca-cert>. Issues the
  per-citizen signing certificates stored in the CEI applet and used by
  `AmSemnat.sign(...)`; those are the anchors for verifying the PAdES
  signatures the SDK produces.

Your app owns freshness and revocation — re-fetch on a cadence
appropriate for your trust window.

## Install

```bash
npm install @amsemnat/verifier
```

ESM-only. Server-side: Node 20 LTS or newer (for native
`globalThis.crypto.subtle`). Client-side: any evergreen browser.

## Quick start — passive auth

```ts
import { readFileSync } from "node:fs";
import { verifyPassive } from "@amsemnat/verifier";

const csca = readFileSync("./csca-romania.cer"); // DER, fetched from DGP

const result = await verifyPassive({
  rawSod: req.body.rawSod,             // RomanianIdentity.rawSod from the mobile SDK
  dataGroups: {
    1: req.body.rawDg1,
    2: req.body.rawDg2,
    14: req.body.rawDg14,
  },
  trustAnchors: [csca],
});

if (!result.valid) {
  console.error("Passive auth failed:", result.errors);
}
```

## Quick start — PAdES signature (Node)

```ts
import { readFileSync } from "node:fs";
import { verifyPadesSignatures } from "@amsemnat/verifier";

const root = readFileSync("./ro-cei-mai-root-ca.cer");
const sub = readFileSync("./ro-cei-mai-sub-ca.cer");

const results = await verifyPadesSignatures({
  pdf: readFileSync("./signed.pdf"),
  trustAnchors: [root, sub],
});

for (const sig of results) {
  console.log(
    `#${sig.signatureIndex} [${sig.fieldName ?? "?"}] valid=${sig.valid} ` +
      `signer="${sig.signerCommonName ?? "?"}" ` +
      `coversWholeDocument=${sig.coversWholeDocument}`,
  );
}
```

## Quick start — PAdES signature (browser)

```ts
import { verifyPadesSignatures } from "@amsemnat/verifier";

// Trust anchors fetched as static assets (DER), or bundled. Both work.
const [root, sub] = await Promise.all([
  fetch("/anchors/ro-cei-mai-root-ca.cer").then((r) => r.arrayBuffer()),
  fetch("/anchors/ro-cei-mai-sub-ca.cer").then((r) => r.arrayBuffer()),
]);

async function onFile(file: File) {
  const pdf = new Uint8Array(await file.arrayBuffer());
  const results = await verifyPadesSignatures({
    pdf,
    trustAnchors: [new Uint8Array(root), new Uint8Array(sub)],
  });
  // render `results` in the UI
}
```

The verifier returns `[]` for unsigned PDFs. Each `PadesVerificationResult`
includes:

- `valid` — overall outcome (CMS signature + chain + `signingCertificateV2` binding).
- `errors` — human-readable failure strings; empty when `valid: true`.
- `signerCommonName`, `signedAt` — best-effort metadata.
- `signatureIndex`, `fieldName` — multi-sig disambiguation.
- `byteRange`, `coversWholeDocument` — caller decides whether
  `valid && coversWholeDocument` is the right policy for "trust this PDF
  end-to-end". A `coversWholeDocument: false` on a non-final signature
  is normal in incremental-update workflows.

## Trust anchors

`trustAnchors` is a flat list of DER-encoded X.509 certificates. The
verifier auto-classifies self-signed entries as roots and the rest as
intermediates — same convention as the mobile SDKs'
`verifyPassiveOffline`. Pass everything in one array.

PEM input is not accepted in 0.1.0. Decode to DER on the caller side
(`pem.replace(/-----.*-----|\s/g, '')` then base64-decode).

## What we do *not* check yet

Documented out of scope for 0.1.0:

- **Timestamp tokens (PAdES B-T).** `signedAt` comes from the
  `signingTime` signed attribute only, not from a TST.
- **CRL / OCSP / LTV.** Freshness and revocation are the consumer's
  responsibility — fetch a current CSCA / DGEP masterlist on a
  reasonable cadence yourself.
- **MRZ / DG1 parsing.** This package verifies; it doesn't parse
  identity. Use the mobile SDK's `RomanianIdentity` object for that.
- **PEM trust anchors.** DER only.

## Public API parity

The top-level result fields (`valid`, `errors`, `signerCommonName`,
`signedAt`) match the mobile SDKs' `verifyPassiveOffline` shape. Cross-
platform code reading either offline or server-side results sees the
same surface for the load-bearing checks.

## License

Apache-2.0. No vendored third-party source. Runtime deps (`pkijs`,
`asn1js`, `pvtsutils`) are MIT-licensed.
