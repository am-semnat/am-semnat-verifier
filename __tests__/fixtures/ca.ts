import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { webcrypto } from "node:crypto";

const subtle = (webcrypto as unknown as Crypto).subtle;

const CN_OID = "2.5.4.3";
const O_OID = "2.5.4.10";
const C_OID = "2.5.4.6";

export interface IssuedCert {
  cert: pkijs.Certificate;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  der: Uint8Array;
}

export interface IssuanceOptions {
  /** Common Name. */
  cn: string;
  organization?: string;
  country?: string;
  notBefore?: Date;
  notAfter?: Date;
  isCa?: boolean;
  /** Sign with this issuer; if omitted the cert is self-signed. */
  issuer?: IssuedCert;
  /** EC named curve. Defaults to P-256. */
  namedCurve?: "P-256" | "P-384";
}

function nameFrom(opts: {
  cn: string;
  organization?: string;
  country?: string;
}): pkijs.RelativeDistinguishedNames {
  const tav: pkijs.AttributeTypeAndValue[] = [];
  if (opts.country) {
    tav.push(
      new pkijs.AttributeTypeAndValue({
        type: C_OID,
        value: new asn1js.PrintableString({ value: opts.country }),
      }),
    );
  }
  if (opts.organization) {
    tav.push(
      new pkijs.AttributeTypeAndValue({
        type: O_OID,
        value: new asn1js.Utf8String({ value: opts.organization }),
      }),
    );
  }
  tav.push(
    new pkijs.AttributeTypeAndValue({
      type: CN_OID,
      value: new asn1js.Utf8String({ value: opts.cn }),
    }),
  );
  return new pkijs.RelativeDistinguishedNames({ typesAndValues: tav });
}

function digestForCurve(curve: "P-256" | "P-384"): "SHA-256" | "SHA-384" {
  return curve === "P-384" ? "SHA-384" : "SHA-256";
}

let serialCounter = 1;

export async function issueCertificate(
  opts: IssuanceOptions,
): Promise<IssuedCert> {
  const curve = opts.namedCurve ?? "P-256";
  const hashAlg = digestForCurve(curve);

  const keypair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: curve },
    true,
    ["sign", "verify"],
  );

  const cert = new pkijs.Certificate();
  cert.version = 2; // X.509 v3
  cert.serialNumber = new asn1js.Integer({ value: serialCounter++ });

  const subjectName = nameFrom(opts);
  cert.subject = subjectName;

  const isSelfSigned = !opts.issuer;
  cert.issuer = isSelfSigned ? subjectName : opts.issuer!.cert.subject;

  const notBefore = opts.notBefore ?? new Date(Date.now() - 60_000);
  const notAfter =
    opts.notAfter ?? new Date(Date.now() + 365 * 24 * 3600 * 1000);
  cert.notBefore.value = notBefore;
  cert.notAfter.value = notAfter;

  await cert.subjectPublicKeyInfo.importKey(keypair.publicKey);

  if (opts.isCa) {
    const basicConstraints = new pkijs.BasicConstraints({
      cA: true,
      pathLenConstraint: 0,
    });
    cert.extensions = [
      new pkijs.Extension({
        extnID: "2.5.29.19",
        critical: true,
        extnValue: basicConstraints.toSchema().toBER(false),
        parsedValue: basicConstraints,
      }),
    ];
  }

  const signerKey = opts.issuer ? opts.issuer.privateKey : keypair.privateKey;
  await cert.sign(signerKey, hashAlg);

  const der = new Uint8Array(cert.toSchema(true).toBER(false));
  return {
    cert,
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    der,
  };
}
