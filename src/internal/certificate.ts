import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

const HASH_OID_MAP: Record<string, string> = {
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
  "2.16.840.1.101.3.4.2.4": "SHA-224",
};

export function hashAlgorithmFromOid(oid: string): string {
  const name = HASH_OID_MAP[oid];
  if (!name) {
    throw new Error(`Unknown hash algorithm OID: ${oid}`);
  }
  return name;
}

export interface TrustAnchors {
  roots: pkijs.Certificate[];
  intermediates: pkijs.Certificate[];
}

export function parseCertificate(der: Uint8Array): pkijs.Certificate {
  const buf = derToArrayBuffer(der);
  const asn1 = asn1js.fromBER(buf);
  if (asn1.offset === -1) {
    throw new Error("Failed to parse certificate DER");
  }
  return new pkijs.Certificate({ schema: asn1.result });
}

function derToArrayBuffer(der: Uint8Array): ArrayBuffer {
  return der.buffer.slice(
    der.byteOffset,
    der.byteOffset + der.byteLength,
  ) as ArrayBuffer;
}

/**
 * Classify a flat list of trust-anchor certs into roots vs intermediates by
 * self-signedness — issuer DN === subject DN. Mirrors the mobile SDK's
 * `verifyPassiveOffline`, which also accepts a flat list.
 */
export function partitionAnchors(certs: pkijs.Certificate[]): TrustAnchors {
  const roots: pkijs.Certificate[] = [];
  const intermediates: pkijs.Certificate[] = [];
  for (const c of certs) {
    if (c.issuer.isEqual(c.subject)) {
      roots.push(c);
    } else {
      intermediates.push(c);
    }
  }
  return { roots, intermediates };
}

export function parseAnchors(ders: Uint8Array[]): TrustAnchors {
  return partitionAnchors(ders.map(parseCertificate));
}

/**
 * Verify a signer cert chain against caller-supplied trust anchors. Used for
 * eMRTD passive auth (DSC → CSCA Romania) and PAdES signer verification
 * (CitizenCert → Sub-CA → Root-CA). Returns `valid: true` only if the chain
 * builds AND the signer is within its validity period.
 */
export async function verifyCertificateChain(
  signer: pkijs.Certificate,
  anchors: TrustAnchors,
): Promise<{ valid: boolean; error?: string }> {
  const { roots, intermediates } = anchors;

  if (roots.length === 0) {
    return { valid: false, error: "No trusted root CA certificates provided" };
  }

  const now = new Date();
  const notBefore = signer.notBefore.value;
  const notAfter = signer.notAfter.value;
  if (now < notBefore || now > notAfter) {
    return {
      valid: false,
      error: `Signer expired or not yet valid (${notBefore.toISOString()} - ${notAfter.toISOString()})`,
    };
  }

  try {
    const chainEngine = new pkijs.CertificateChainValidationEngine({
      trustedCerts: roots,
      certs: [signer, ...intermediates],
    });
    const result = await chainEngine.verify();
    if (!result.result) {
      return {
        valid: false,
        error: result.resultMessage || "Certificate chain validation failed",
      };
    }
    return { valid: true };
  } catch (e) {
    return {
      valid: false,
      error: `Chain verification error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/**
 * Best-effort common-name extraction from a certificate's subject DN. Returns
 * `null` if no CN attribute is present.
 */
export function commonNameOf(cert: pkijs.Certificate): string | null {
  const CN_OID = "2.5.4.3";
  for (const rdn of cert.subject.typesAndValues) {
    if (rdn.type === CN_OID) {
      const v = rdn.value.valueBlock.value as unknown;
      if (typeof v === "string") return v;
    }
  }
  return null;
}
