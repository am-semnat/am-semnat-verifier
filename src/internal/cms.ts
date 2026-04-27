import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { createHash } from "node:crypto";

const SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47";
const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const SHA1_OID = "1.3.14.3.2.26";
const SHA384_OID = "2.16.840.1.101.3.4.2.2";
const SHA512_OID = "2.16.840.1.101.3.4.2.3";
const SHA224_OID = "2.16.840.1.101.3.4.2.4";

const HASH_ALG_BY_OID: Record<string, string> = {
  [SHA1_OID]: "sha1",
  [SHA224_OID]: "sha224",
  [SHA256_OID]: "sha256",
  [SHA384_OID]: "sha384",
  [SHA512_OID]: "sha512",
};

export interface CmsVerificationOutcome {
  valid: boolean;
  error?: string;
  signerCert: pkijs.Certificate;
  signedAt: Date | null;
  digestAlgorithmOid: string | null;
}

/**
 * Verify a CMS SignedData structure: signature over the eContent (or
 * detachedContent if supplied), plus the ETSI EN 319 122 signingCertificateV2
 * binding check. Used by both passive auth (eContent embedded in SOD) and
 * PAdES B-B (detachedContent = signed PDF byte ranges).
 *
 * Does NOT verify the signer cert chain — caller runs that separately against
 * the appropriate trust anchors (CSCA Romania for passive, DGEP CEI for PAdES).
 */
export async function verifyCmsSignedData(
  signedData: pkijs.SignedData,
  detachedContent?: ArrayBuffer,
): Promise<CmsVerificationOutcome> {
  const signerCert = pickSignerCert(signedData);
  const signedAt = extractSigningTime(signedData);
  const digestAlgorithmOid = extractDigestAlgorithmOid(signedData);

  if (!signerCert) {
    return {
      valid: false,
      error: "CMS SignedData has no signer certificate",
      signerCert: new pkijs.Certificate(),
      signedAt,
      digestAlgorithmOid,
    };
  }

  const bindingError = verifySigningCertificateV2(signedData, signerCert);
  if (bindingError) {
    return {
      valid: false,
      error: bindingError,
      signerCert,
      signedAt,
      digestAlgorithmOid,
    };
  }

  try {
    const result = detachedContent
      ? await signedData.verify({
          signer: 0,
          checkChain: false,
          data: detachedContent,
          extendedMode: false,
        })
      : await signedData.verify({
          signer: 0,
          checkChain: false,
          extendedMode: false,
        });
    if (!result) {
      return {
        valid: false,
        error: "CMS signature verification failed",
        signerCert,
        signedAt,
        digestAlgorithmOid,
      };
    }
    return {
      valid: true,
      signerCert,
      signedAt,
      digestAlgorithmOid,
    };
  } catch (e) {
    return {
      valid: false,
      error: `CMS signature verification error: ${e instanceof Error ? e.message : String(e)}`,
      signerCert,
      signedAt,
      digestAlgorithmOid,
    };
  }
}

function pickSignerCert(signedData: pkijs.SignedData): pkijs.Certificate | null {
  const certs = (signedData.certificates ?? []).filter(
    (c): c is pkijs.Certificate => c instanceof pkijs.Certificate,
  );
  if (certs.length === 0) return null;

  const signerInfo = signedData.signerInfos?.[0];
  if (!signerInfo) return certs[0] ?? null;

  // Try to match by IssuerAndSerialNumber from SignerInfo.sid.
  const sid = signerInfo.sid as unknown;
  if (sid instanceof pkijs.IssuerAndSerialNumber) {
    for (const cert of certs) {
      if (
        cert.issuer.isEqual(sid.issuer) &&
        cert.serialNumber.isEqual(sid.serialNumber)
      ) {
        return cert;
      }
    }
  }
  return certs[0] ?? null;
}

function extractDigestAlgorithmOid(
  signedData: pkijs.SignedData,
): string | null {
  const signerInfo = signedData.signerInfos?.[0];
  if (!signerInfo) return null;
  return signerInfo.digestAlgorithm.algorithmId ?? null;
}

function extractSigningTime(signedData: pkijs.SignedData): Date | null {
  const attrs = signedData.signerInfos?.[0]?.signedAttrs?.attributes ?? [];
  for (const attr of attrs) {
    if (attr.type !== SIGNING_TIME_OID) continue;
    const value = attr.values?.[0];
    if (!value) continue;
    if (value instanceof asn1js.UTCTime) return value.toDate();
    if (value instanceof asn1js.GeneralizedTime) return value.toDate();
  }
  return null;
}

/**
 * ETSI EN 319 122 §5.2.2.3: the signingCertificateV2 signed attribute MUST
 * cryptographically bind the signed attributes to the signer certificate.
 * Without this check pkijs will happily verify a SignedData where the embedded
 * signer cert was swapped for another. Returns an error message string if the
 * check fails, or null if the binding holds (or the attribute is absent on a
 * signed-attrs-less CMS, which is rare and only valid for content with
 * specific MIME types — we accept this case for SOD compatibility but
 * tighten it for PAdES via the caller, which always has signedAttrs).
 */
function verifySigningCertificateV2(
  signedData: pkijs.SignedData,
  signerCert: pkijs.Certificate,
): string | null {
  const attrs = signedData.signerInfos?.[0]?.signedAttrs?.attributes ?? [];
  const sigCertAttr = attrs.find((a) => a.type === SIGNING_CERTIFICATE_V2_OID);

  // SODs typically lack signingCertificateV2 — that's OK for ICAO eMRTD.
  // PAdES B-B requires it; the PAdES caller enforces presence separately.
  if (!sigCertAttr) return null;

  const value = sigCertAttr.values?.[0];
  if (!value) return "signingCertificateV2 attribute is empty";

  // SigningCertificateV2 ::= SEQUENCE {
  //   certs SEQUENCE OF ESSCertIDv2,
  //   policies SEQUENCE OF PolicyInformation OPTIONAL
  // }
  // ESSCertIDv2 ::= SEQUENCE {
  //   hashAlgorithm AlgorithmIdentifier DEFAULT { id-sha256 },
  //   certHash OCTET STRING,
  //   issuerSerial IssuerSerial OPTIONAL
  // }

  const outer = value as asn1js.Sequence;
  const certsSeq = outer.valueBlock.value[0] as asn1js.Sequence | undefined;
  const firstCertId = certsSeq?.valueBlock.value[0] as asn1js.Sequence | undefined;
  if (!firstCertId) {
    return "signingCertificateV2 contains no ESSCertIDv2 entries";
  }

  let hashOid = SHA256_OID;
  let certHashOctets: asn1js.OctetString | undefined;
  const inner = firstCertId.valueBlock.value;
  let cursor = 0;

  // Optional AlgorithmIdentifier
  if (inner[cursor] instanceof asn1js.Sequence) {
    const algSeq = inner[cursor] as asn1js.Sequence;
    const oid = algSeq.valueBlock.value[0] as asn1js.ObjectIdentifier | undefined;
    if (oid) hashOid = oid.valueBlock.toString();
    cursor++;
  }

  // certHash (OCTET STRING) is required
  if (inner[cursor] instanceof asn1js.OctetString) {
    certHashOctets = inner[cursor] as asn1js.OctetString;
    cursor++;
  }

  if (!certHashOctets) {
    return "signingCertificateV2 missing certHash";
  }

  const expected = new Uint8Array(certHashOctets.valueBlock.valueHexView);
  const nodeAlg = HASH_ALG_BY_OID[hashOid];
  if (!nodeAlg) {
    return `signingCertificateV2 unsupported hash algorithm OID ${hashOid}`;
  }

  const certDerBuf = signerCert.toSchema(true).toBER(false);
  const certDer = new Uint8Array(certDerBuf);
  const computed = new Uint8Array(
    createHash(nodeAlg).update(certDer).digest(),
  );

  if (computed.length !== expected.length) {
    return `signingCertificateV2 cert hash length mismatch (alg=${nodeAlg})`;
  }
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= (computed[i] as number) ^ (expected[i] as number);
  }
  if (diff !== 0) {
    return "signingCertificateV2 cert hash does not match embedded signer certificate";
  }
  return null;
}
