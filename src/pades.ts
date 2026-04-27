import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
  commonNameOf,
  parseAnchors,
  verifyCertificateChain,
} from "./internal/certificate.js";
import { verifyCmsSignedData } from "./internal/cms.js";
import { extractSignatures } from "./internal/pdf-signatures.js";
import { describe } from "./internal/errors.js";
import type {
  PadesVerificationInput,
  PadesVerificationResult,
} from "./public-types.js";

const SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47";
const ACCEPTED_SUBFILTERS = new Set([
  "ETSI.CAdES.detached",
  "ETSI.CAdES.attached", // not B-B per spec but accept defensively; keys off CMS shape
  "adbe.pkcs7.detached",
]);
const REJECTED_SUBFILTERS = new Set(["adbe.x509.rsa_sha1"]);

/**
 * Verify every PAdES signature in a signed PDF. Returns one result per
 * signature in document order; never throws on malformed signatures — instead
 * captures the failure under `errors` and `valid: false`. An unsigned PDF
 * returns `[]`.
 */
export async function verifyPadesSignatures(
  input: PadesVerificationInput,
): Promise<PadesVerificationResult[]> {
  const sigs = extractSignatures(input.pdf);
  const anchors = parseAnchors(input.trustAnchors);

  const results: PadesVerificationResult[] = [];
  for (const sig of sigs) {
    const errors: string[] = [];
    let signerCommonName: string | null = null;
    let signedAt: Date | null = null;
    let cmsValid = false;
    let chainValid = false;

    if (sig.subFilter && REJECTED_SUBFILTERS.has(sig.subFilter)) {
      errors.push(
        `Rejected legacy /SubFilter ${sig.subFilter} — only PAdES B-B is supported`,
      );
    } else if (sig.subFilter && !ACCEPTED_SUBFILTERS.has(sig.subFilter)) {
      errors.push(`Unsupported /SubFilter ${sig.subFilter}`);
    }

    let signedData: pkijs.SignedData | null = null;
    try {
      signedData = parseSignedDataCms(sig.contents);
    } catch (e) {
      errors.push(describe("CMS parse failed", e));
    }

    if (signedData) {
      if (!hasSigningCertificateV2(signedData)) {
        errors.push(
          "PAdES B-B signature missing required signingCertificateV2 attribute",
        );
      }

      const cmsOutcome = await verifyCmsSignedData(
        signedData,
        toArrayBuffer(sig.signedBytes),
      );
      cmsValid = cmsOutcome.valid;
      signedAt = cmsOutcome.signedAt;
      signerCommonName = commonNameOf(cmsOutcome.signerCert);
      if (!cmsOutcome.valid && cmsOutcome.error) {
        errors.push(cmsOutcome.error);
      }

      try {
        const chainResult = await verifyCertificateChain(
          cmsOutcome.signerCert,
          anchors,
        );
        chainValid = chainResult.valid;
        if (!chainResult.valid && chainResult.error) {
          errors.push(`Certificate chain: ${chainResult.error}`);
        }
      } catch (e) {
        errors.push(describe("Certificate chain error", e));
      }
    }

    const valid = errors.length === 0 && cmsValid && chainValid;

    results.push({
      valid,
      errors,
      signerCommonName,
      signedAt,
      signatureIndex: sig.signatureIndex,
      fieldName: sig.fieldName,
      byteRange: sig.byteRange,
      coversWholeDocument: sig.coversWholeDocument,
    });
  }
  return results;
}

function parseSignedDataCms(cmsDer: Uint8Array): pkijs.SignedData {
  const buf = cmsDer.buffer.slice(
    cmsDer.byteOffset,
    cmsDer.byteOffset + cmsDer.byteLength,
  ) as ArrayBuffer;
  const asn1 = asn1js.fromBER(buf);
  if (asn1.offset === -1) {
    throw new Error("Invalid CMS DER encoding");
  }
  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  if (contentInfo.contentType !== "1.2.840.113549.1.7.2") {
    throw new Error(
      `CMS contentType is not SignedData (got ${contentInfo.contentType})`,
    );
  }
  return new pkijs.SignedData({ schema: contentInfo.content });
}

function hasSigningCertificateV2(signedData: pkijs.SignedData): boolean {
  const attrs = signedData.signerInfos?.[0]?.signedAttrs?.attributes ?? [];
  return attrs.some((a) => a.type === SIGNING_CERTIFICATE_V2_OID);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}
