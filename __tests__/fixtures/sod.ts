import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { createHash } from "node:crypto";
import type { IssuedCert } from "./ca.js";

const ICAO_LDS_SECURITY_OBJECT_OID = "2.23.136.1.1.1";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";

export interface BuildSodOptions {
  dsc: IssuedCert;
  /** DG number → raw bytes. */
  dataGroups: Map<number, Uint8Array>;
  /** Wrap in the ICAO 0x77 EF.SOD application tag. Defaults to true (matches `RomanianIdentity.rawSod`). */
  wrapEmrtdEnvelope?: boolean;
}

/**
 * Build a synthetic eMRTD SOD: LDSSecurityObject (SHA-256 hashes of supplied
 * DG bytes), wrapped as eContent in a CMS SignedData signed by `dsc`.
 */
export async function buildSod(opts: BuildSodOptions): Promise<Uint8Array> {
  const ldsBytes = buildLdsSecurityObject(opts.dataGroups);

  const messageDigest = createHash("sha256").update(ldsBytes).digest();

  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      // contentType
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.3",
        values: [
          new asn1js.ObjectIdentifier({ value: ICAO_LDS_SECURITY_OBJECT_OID }),
        ],
      }),
      // signingTime (optional but commonly present)
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.5",
        values: [new asn1js.UTCTime({ valueDate: new Date() })],
      }),
      // messageDigest
      new pkijs.Attribute({
        type: "1.2.840.113549.1.9.4",
        values: [new asn1js.OctetString({ valueHex: messageDigest })],
      }),
    ],
  });

  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: opts.dsc.cert.issuer,
      serialNumber: opts.dsc.cert.serialNumber,
    }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: SHA256_OID,
    }),
    signedAttrs,
  });

  const signedData = new pkijs.SignedData({
    version: 3,
    digestAlgorithms: [
      new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
    ],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: ICAO_LDS_SECURITY_OBJECT_OID,
      eContent: new asn1js.OctetString({ valueHex: ldsBytes }),
    }),
    signerInfos: [signerInfo],
    certificates: [opts.dsc.cert],
  });

  await signedData.sign(opts.dsc.privateKey, 0, "SHA-256");

  const contentInfo = new pkijs.ContentInfo({
    contentType: "1.2.840.113549.1.7.2",
    content: signedData.toSchema(true),
  });
  const cmsBer = new Uint8Array(contentInfo.toSchema().toBER(false));

  const wrap = opts.wrapEmrtdEnvelope ?? true;
  return wrap ? wrapEmrtdEnvelope(cmsBer) : cmsBer;
}

function buildLdsSecurityObject(
  dataGroups: Map<number, Uint8Array>,
): Uint8Array {
  const dgEntries: asn1js.Sequence[] = [];
  const sortedNumbers = [...dataGroups.keys()].sort((a, b) => a - b);
  for (const n of sortedNumbers) {
    const bytes = dataGroups.get(n)!;
    const hash = createHash("sha256").update(bytes).digest();
    dgEntries.push(
      new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: n }),
          new asn1js.OctetString({ valueHex: hash }),
        ],
      }),
    );
  }

  const lds = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: SHA256_OID }),
          new asn1js.Null(),
        ],
      }),
      new asn1js.Sequence({ value: dgEntries }),
    ],
  });
  return new Uint8Array(lds.toBER(false));
}

/**
 * Wrap CMS DER in the ICAO eMRTD EF.SOD outer TLV (application tag 0x77).
 */
function wrapEmrtdEnvelope(cms: Uint8Array): Uint8Array {
  const len = encodeBerLength(cms.length);
  const out = new Uint8Array(1 + len.length + cms.length);
  out[0] = 0x77;
  out.set(len, 1);
  out.set(cms, 1 + len.length);
  return out;
}

function encodeBerLength(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}
