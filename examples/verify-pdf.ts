import { readFileSync } from "node:fs";
import { argv } from "node:process";
import { verifyPadesSignatures } from "@amsemnat/verifier";

const [pdfPath, ...anchorPaths] = argv.slice(2);

if (!pdfPath || anchorPaths.length === 0) {
  console.error(
    "usage: verify-pdf <signed.pdf> <root.cer> [<sub-ca.cer> ...]\n" +
      "  fetch DGEP anchors (RO CEI MAI Root-CA / Sub-CA) from MAI's publication point",
  );
  process.exit(2);
}

const pdf = readFileSync(pdfPath);
const trustAnchors = anchorPaths.map((p) => readFileSync(p));

const results = await verifyPadesSignatures({ pdf, trustAnchors });

if (results.length === 0) {
  console.log("PDF contains no PAdES signatures.");
  process.exit(1);
}

let allValid = true;
for (const sig of results) {
  const status = sig.valid ? "VALID" : "INVALID";
  console.log(
    `[${status}] #${sig.signatureIndex} field="${sig.fieldName ?? "?"}" ` +
      `signer="${sig.signerCommonName ?? "?"}" ` +
      `signedAt=${sig.signedAt?.toISOString() ?? "?"} ` +
      `coversWholeDocument=${sig.coversWholeDocument}`,
  );
  for (const err of sig.errors) console.log(`  - ${err}`);
  if (!sig.valid) allValid = false;
}

process.exit(allValid ? 0 : 1);
