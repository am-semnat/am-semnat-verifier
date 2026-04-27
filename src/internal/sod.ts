import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

export interface SodContents {
  /** The Document Signing Certificate extracted from the CMS. */
  dsc: pkijs.Certificate;
  /** The CMS SignedData structure. */
  signedData: pkijs.SignedData;
  /** The LDS Security Object (encapsulated content) as raw bytes. */
  ldsSecurityObjectBytes: Uint8Array;
  /** Digest algorithm OID used for DG hashes. */
  hashAlgorithmOid: string;
  /** Map of data group number → expected hash from the signed security object. */
  dataGroupHashes: Map<number, Uint8Array>;
}

/**
 * If the input starts with the ICAO eMRTD EF.SOD application tag (0x77), strip
 * the outer TLV and return the inner CMS ContentInfo bytes. Otherwise return
 * the input unchanged. Lets the parser accept both raw inner CMS and full
 * EF.SOD bytes (`RomanianIdentity.rawSod` from the mobile SDKs).
 */
function unwrapEmrtdSod(bytes: ArrayBuffer): ArrayBuffer {
  const view = new Uint8Array(bytes);
  if (view.length === 0 || view[0] !== 0x77) {
    return bytes;
  }
  let lenOffset = 1;
  const first = view[1];
  if (first === undefined) return bytes;
  if (first & 0x80) {
    lenOffset += 1 + (first & 0x7f);
  } else {
    lenOffset += 1;
  }
  return view.slice(lenOffset).buffer;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

/**
 * Parse an SOD (Security Object Document) from CMS DER bytes.
 *
 * The SOD is a CMS SignedData structure (RFC 5652) containing a Document
 * Signing Certificate, a signature over the LDS Security Object, and the LDS
 * Security Object itself (ICAO 9303 Part 10) which carries per-data-group
 * hashes.
 */
export function parseSod(rawSod: Uint8Array): SodContents {
  const derBytes = unwrapEmrtdSod(toArrayBuffer(rawSod));
  const asn1 = asn1js.fromBER(derBytes);
  if (asn1.offset === -1) {
    throw new Error("Failed to parse SOD: invalid DER encoding");
  }

  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  if (contentInfo.contentType !== "1.2.840.113549.1.7.2") {
    throw new Error(
      `SOD is not SignedData: contentType=${contentInfo.contentType}`,
    );
  }

  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  if (!signedData.certificates || signedData.certificates.length === 0) {
    throw new Error("SOD contains no certificates");
  }
  const dsc = signedData.certificates[0] as pkijs.Certificate;

  if (!signedData.encapContentInfo || !signedData.encapContentInfo.eContent) {
    throw new Error("SOD has no encapsulated content");
  }

  const eContentAsn1 = signedData.encapContentInfo.eContent;
  const ldsSecurityObjectBytes = new Uint8Array(eContentAsn1.getValue());

  const { hashAlgorithmOid, dataGroupHashes } = parseLdsSecurityObject(
    ldsSecurityObjectBytes,
  );

  return {
    dsc,
    signedData,
    ldsSecurityObjectBytes,
    hashAlgorithmOid,
    dataGroupHashes,
  };
}

/**
 * Parse the LDS Security Object (ICAO 9303 Part 10).
 *
 *   LDSSecurityObject ::= SEQUENCE {
 *     version              INTEGER,
 *     hashAlgorithm        AlgorithmIdentifier,
 *     dataGroupHashValues  SEQUENCE OF DataGroupHash
 *   }
 */
function parseLdsSecurityObject(bytes: Uint8Array): {
  hashAlgorithmOid: string;
  dataGroupHashes: Map<number, Uint8Array>;
} {
  const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
  if (asn1.offset === -1) {
    throw new Error("Failed to parse LDS Security Object");
  }

  const sequence = asn1.result as asn1js.Sequence;
  const values = sequence.valueBlock.value;

  const algSeq = values[1] as asn1js.Sequence;
  const algOid = (algSeq.valueBlock.value[0] as asn1js.ObjectIdentifier)
    .valueBlock.toString();

  const dgHashSeq = values[2] as asn1js.Sequence;
  const dataGroupHashes = new Map<number, Uint8Array>();

  for (const dgHash of dgHashSeq.valueBlock.value) {
    const dgSeq = dgHash as asn1js.Sequence;
    const dgNumber = (dgSeq.valueBlock.value[0] as asn1js.Integer).valueBlock
      .valueDec;
    const dgHashValue = new Uint8Array(
      (dgSeq.valueBlock.value[1] as asn1js.OctetString).valueBlock.valueHexView,
    );
    dataGroupHashes.set(dgNumber, dgHashValue);
  }

  return { hashAlgorithmOid: algOid, dataGroupHashes };
}
