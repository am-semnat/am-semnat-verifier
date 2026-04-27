import { webcrypto } from "node:crypto";
import { issueCertificate, type IssuedCert } from "./ca.js";
import { buildSod } from "./sod.js";
import { appendSecondSignature, buildSignedPdf } from "./pdf.js";

const cryptoApi = webcrypto as unknown as Crypto;

export interface PassiveFixture {
  rawSod: Uint8Array;
  dataGroups: Record<number, Uint8Array>;
  trustAnchors: Uint8Array[];
  csca: IssuedCert;
  dsc: IssuedCert;
}

export interface BuildPassiveFixtureOptions {
  /** DG number whose bytes should be flipped after SOD is signed (forces hash mismatch). */
  tamperDg?: number;
  /** Issue DSC with notAfter in the past. */
  expireDsc?: boolean;
  /** Return a different self-signed CSCA as the trust anchor. */
  wrongAnchor?: boolean;
  /** Drop a DG from the supplied dataGroups even though SOD lists it. */
  dropDg?: number;
}

/**
 * Build a synthetic eMRTD passive auth bundle: self-signed CSCA, DSC issued
 * under it, SOD signed by DSC over SHA-256 hashes of synthetic DG1/DG2/DG14
 * bytes. Returned bytes match the on-the-wire shapes the mobile SDKs emit.
 */
export async function buildPassiveFixture(
  opts: BuildPassiveFixtureOptions = {},
): Promise<PassiveFixture> {
  const csca = await issueCertificate({
    cn: "Synthetic CSCA Romania",
    organization: "Synthetic DGP",
    country: "RO",
    isCa: true,
  });

  const dscNotBefore = opts.expireDsc
    ? new Date(Date.now() - 90 * 24 * 3600 * 1000)
    : undefined;
  const dscNotAfter = opts.expireDsc
    ? new Date(Date.now() - 24 * 3600 * 1000)
    : undefined;

  const dsc = await issueCertificate({
    cn: "Synthetic DSC",
    organization: "Synthetic DGP",
    country: "RO",
    issuer: csca,
    notBefore: dscNotBefore,
    notAfter: dscNotAfter,
  });

  const dg1 = randomBytes(88);
  const dg2 = randomBytes(600);
  const dg14 = randomBytes(220);

  const dgsForSod = new Map<number, Uint8Array>([
    [1, dg1],
    [2, dg2],
    [14, dg14],
  ]);

  const rawSod = await buildSod({ dsc, dataGroups: dgsForSod });

  const dgsOut: Record<number, Uint8Array> = {};
  if (opts.dropDg !== 1) dgsOut[1] = dg1;
  if (opts.dropDg !== 2) dgsOut[2] = dg2;
  if (opts.dropDg !== 14) dgsOut[14] = dg14;

  if (opts.tamperDg !== undefined) {
    const target = dgsOut[opts.tamperDg];
    if (target && target.length > 0) {
      target[0] = (target[0] as number) ^ 0xff;
    }
  }

  let trustAnchors: Uint8Array[];
  if (opts.wrongAnchor) {
    const otherCsca = await issueCertificate({
      cn: "Synthetic Wrong CSCA",
      isCa: true,
    });
    trustAnchors = [otherCsca.der];
  } else {
    trustAnchors = [csca.der];
  }

  return { rawSod, dataGroups: dgsOut, trustAnchors, csca, dsc };
}

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  cryptoApi.getRandomValues(buf);
  return buf;
}

export interface PadesFixture {
  pdf: Uint8Array;
  trustAnchors: Uint8Array[];
  root: IssuedCert;
  subCa: IssuedCert;
  citizen: IssuedCert;
}

export interface BuildPadesFixtureOptions {
  /** Number of signatures in the resulting PDF. Default 1. Max 2 in 0.1.0 fixtures. */
  numSignatures?: 1 | 2;
  /** Append bytes to the PDF after the final signature, breaking coversWholeDocument. */
  tamperAfterSign?: boolean;
  /** Issue the citizen cert with notAfter in the past. */
  expiredCitizen?: boolean;
  /** Return a different self-signed root as the trust anchor. */
  wrongAnchor?: boolean;
  /** Skip embedding any signature; result is a plain unsigned PDF. */
  unsigned?: boolean;
}

/**
 * Build a synthetic PAdES B-B bundle: synthetic DGEP-style PKI (Root → Sub-CA
 * → CitizenCert) and a hand-rolled tiny PDF carrying one or two signatures.
 */
export async function buildPadesFixture(
  opts: BuildPadesFixtureOptions = {},
): Promise<PadesFixture> {
  const root = await issueCertificate({
    cn: "Synthetic RO CEI MAI Root-CA",
    organization: "Synthetic DGEP",
    country: "RO",
    isCa: true,
  });
  const subCa = await issueCertificate({
    cn: "Synthetic RO CEI MAI Sub-CA",
    organization: "Synthetic DGEP",
    country: "RO",
    isCa: true,
    issuer: root,
  });

  const citizenNotBefore = opts.expiredCitizen
    ? new Date(Date.now() - 90 * 24 * 3600 * 1000)
    : undefined;
  const citizenNotAfter = opts.expiredCitizen
    ? new Date(Date.now() - 24 * 3600 * 1000)
    : undefined;

  const citizen = await issueCertificate({
    cn: "POPESCU ION",
    organization: "Synthetic CEI Holder",
    country: "RO",
    issuer: subCa,
    notBefore: citizenNotBefore,
    notAfter: citizenNotAfter,
  });

  let pdf: Uint8Array;
  if (opts.unsigned) {
    pdf = unsignedPdf();
  } else {
    pdf = await buildSignedPdf({ citizen, fieldName: "Signature1" });
    if ((opts.numSignatures ?? 1) === 2) {
      pdf = await appendSecondSignature(pdf, {
        citizen,
        fieldName: "Signature2",
      });
    }
  }

  if (opts.tamperAfterSign) {
    const trailer = new TextEncoder().encode("\n% tampered\n");
    const grown = new Uint8Array(pdf.length + trailer.length);
    grown.set(pdf, 0);
    grown.set(trailer, pdf.length);
    pdf = grown;
  }

  let trustAnchors: Uint8Array[];
  if (opts.wrongAnchor) {
    const otherRoot = await issueCertificate({
      cn: "Synthetic Wrong Root",
      isCa: true,
    });
    trustAnchors = [otherRoot.der];
  } else {
    trustAnchors = [root.der, subCa.der];
  }

  return { pdf, trustAnchors, root, subCa, citizen };
}

function unsignedPdf(): Uint8Array {
  const text =
    "%PDF-1.4\n" +
    "%\xc0\xc0\xc0\xc0\n" +
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
    "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
    "xref\n0 3\n" +
    "0000000000 65535 f \n" +
    "0000000009 00000 n \n" +
    "0000000063 00000 n \n" +
    "trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n";
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}
