import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { createHash } from "node:crypto";
import type { IssuedCert } from "./ca.js";

const SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const PDF_DATA_OID = "1.2.840.113549.1.7.1";

const PLACEHOLDER_BYTES = 8192;
const PLACEHOLDER_HEX_LEN = PLACEHOLDER_BYTES * 2;

export interface PadesSignatureSpec {
  citizen: IssuedCert;
  fieldName: string;
}

/**
 * Build a minimal hand-rolled PDF with one PAdES B-B signature applied. Not
 * Adobe-grade — just enough structure (correctly placed /ByteRange and
 * /Contents inside a `/Type /Sig` dict, valid CMS) to drive the verifier under
 * test.
 */
export async function buildSignedPdf(
  spec: PadesSignatureSpec,
): Promise<Uint8Array> {
  const placeholder = "0".repeat(PLACEHOLDER_HEX_LEN);
  const trailingDocBytes = encodeUtf8("\n");

  // Reserve fixed widths so placeholder substitution preserves byte offsets.
  const byteRangePlaceholder = "/ByteRange [0000000000 0000000000 0000000000 0000000000]";

  const skeleton =
    "%PDF-1.4\n" +
    "%\xc0\xc0\xc0\xc0\n" +
    "1 0 obj\n" +
    "<< /Type /Catalog /Pages 2 0 R >>\n" +
    "endobj\n" +
    "2 0 obj\n" +
    "<< /Type /Pages /Kids [] /Count 0 >>\n" +
    "endobj\n" +
    "3 0 obj\n" +
    "<< /Type /Sig" +
    " /Filter /Adobe.PPKLite" +
    " /SubFilter /ETSI.CAdES.detached" +
    " /M (D:20260427150000+00'00')" +
    " /T (" + spec.fieldName + ")" +
    " " + byteRangePlaceholder +
    " /Contents <" + placeholder + ">" +
    " >>\n" +
    "endobj\n" +
    "xref\n" +
    "0 4\n" +
    "0000000000 65535 f \n" +
    "0000000009 00000 n \n" +
    "0000000063 00000 n \n" +
    "0000000111 00000 n \n" +
    "trailer\n" +
    "<< /Size 4 /Root 1 0 R >>\n" +
    "startxref\n" +
    "0\n" +
    "%%EOF\n";

  const skeletonBytes = encodeLatin1(skeleton);
  const fullBytes = concat(skeletonBytes, trailingDocBytes);

  const pdfBytes = await applySignature(fullBytes, spec);
  return pdfBytes;
}

/**
 * Apply a second incremental-update signature to an already-signed PDF.
 * Result has two `/Type /Sig` dicts; only the second covers the whole final
 * document.
 */
export async function appendSecondSignature(
  base: Uint8Array,
  spec: PadesSignatureSpec,
): Promise<Uint8Array> {
  const placeholder = "0".repeat(PLACEHOLDER_HEX_LEN);
  const byteRangePlaceholder = "/ByteRange [0000000000 0000000000 0000000000 0000000000]";

  const update =
    "\n" +
    "4 0 obj\n" +
    "<< /Type /Sig" +
    " /Filter /Adobe.PPKLite" +
    " /SubFilter /ETSI.CAdES.detached" +
    " /M (D:20260427160000+00'00')" +
    " /T (" + spec.fieldName + ")" +
    " " + byteRangePlaceholder +
    " /Contents <" + placeholder + ">" +
    " >>\n" +
    "endobj\n" +
    "xref\n" +
    "0 1\n" +
    "0000000000 65535 f \n" +
    "trailer\n" +
    "<< /Size 5 /Root 1 0 R /Prev 0 >>\n" +
    "startxref\n" +
    "0\n" +
    "%%EOF\n";

  const merged = concat(base, encodeLatin1(update));
  return applySignature(merged, spec);
}

async function applySignature(
  pdf: Uint8Array,
  spec: PadesSignatureSpec,
): Promise<Uint8Array> {
  const { brOffset, contentsStart, contentsEnd } = locatePlaceholders(pdf);

  // The signed bytes are everything except the /Contents hex string itself
  // (between the < and the >, exclusive of both).
  const a = 0;
  const b = contentsStart; // up to and including '<'
  const c = contentsEnd; // starting at '>'
  const d = pdf.length - c;

  const byteRangeFinal = formatByteRange(a, b, c, d);
  const placedBr = replaceBytes(pdf, brOffset, byteRangeFinal);

  const signedBytes = concat(
    placedBr.subarray(a, a + b),
    placedBr.subarray(c, c + d),
  );
  const messageDigest = createHash("sha256").update(signedBytes).digest();

  const cms = await buildPadesCms(spec.citizen, messageDigest);

  const cmsHex = bytesToHex(cms);
  if (cmsHex.length > PLACEHOLDER_HEX_LEN) {
    throw new Error(
      `CMS too large for placeholder (${cmsHex.length} > ${PLACEHOLDER_HEX_LEN})`,
    );
  }
  const padded = cmsHex + "0".repeat(PLACEHOLDER_HEX_LEN - cmsHex.length);

  // contentsStart points at '<'; the hex string starts at contentsStart+1.
  return replaceBytes(placedBr, contentsStart + 1, encodeLatin1(padded));
}

function formatByteRange(
  a: number,
  b: number,
  c: number,
  d: number,
): Uint8Array {
  const pad = (n: number) => n.toString().padStart(10, "0");
  const s = `/ByteRange [${pad(a)} ${pad(b)} ${pad(c)} ${pad(d)}]`;
  return encodeLatin1(s);
}

function locatePlaceholders(pdf: Uint8Array): {
  brOffset: number;
  contentsStart: number;
  contentsEnd: number;
} {
  // Find the LAST occurrence of /ByteRange placeholder pattern (the most
  // recently appended signature). Same for /Contents placeholder.
  const text = bytesToLatin1(pdf);
  const brToken = "/ByteRange [0000000000 0000000000 0000000000 0000000000]";
  const cToken = "<" + "0".repeat(PLACEHOLDER_HEX_LEN) + ">";

  const brOffset = text.lastIndexOf(brToken);
  if (brOffset < 0) throw new Error("ByteRange placeholder not found");
  const cStart = text.lastIndexOf(cToken);
  if (cStart < 0) throw new Error("Contents placeholder not found");

  return {
    brOffset,
    contentsStart: cStart, // points at '<'
    contentsEnd: cStart + cToken.length - 1, // points at '>'
  };
}

async function buildPadesCms(
  citizen: IssuedCert,
  messageDigest: Buffer,
): Promise<Uint8Array> {
  const certHash = createHash("sha256").update(citizen.der).digest();

  const signingCertV2 = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [new asn1js.OctetString({ valueHex: certHash })],
          }),
        ],
      }),
    ],
  });

  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.3",
        values: [new asn1js.ObjectIdentifier({ value: PDF_DATA_OID })],
      }),
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.5",
        values: [new asn1js.UTCTime({ valueDate: new Date() })],
      }),
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.4",
        values: [new asn1js.OctetString({ valueHex: messageDigest })],
      }),
      new pkijs.Attribute({
        type: SIGNING_CERTIFICATE_V2_OID,
        values: [signingCertV2],
      }),
    ],
  });

  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: citizen.cert.issuer,
      serialNumber: citizen.cert.serialNumber,
    }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
    signedAttrs,
  });

  const signedData = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [
      new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
    ],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: PDF_DATA_OID,
      // No eContent — detached signature. PAdES B-B requires this.
    }),
    signerInfos: [signerInfo],
    certificates: [citizen.cert],
  });

  await signedData.sign(citizen.privateKey, 0, "SHA-256");

  const contentInfo = new pkijs.ContentInfo({
    contentType: "1.2.840.113549.1.7.2",
    content: signedData.toSchema(true),
  });
  return new Uint8Array(contentInfo.toSchema().toBER(false));
}

function encodeLatin1(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesToLatin1(b: Uint8Array): string {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < b.length; i += CHUNK) {
    s += String.fromCharCode.apply(
      null,
      b.subarray(i, Math.min(i + CHUNK, b.length)) as unknown as number[],
    );
  }
  return s;
}

function bytesToHex(b: Uint8Array): string {
  const HEX = "0123456789abcdef";
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const v = b[i] as number;
    s += HEX[v >> 4];
    s += HEX[v & 0x0f];
  }
  return s;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function replaceBytes(
  src: Uint8Array,
  offset: number,
  replacement: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(src.length);
  out.set(src, 0);
  out.set(replacement, offset);
  return out;
}
