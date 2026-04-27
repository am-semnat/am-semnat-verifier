import { parseSod } from "./internal/sod.js";
import {
  parseAnchors,
  verifyCertificateChain,
  commonNameOf,
} from "./internal/certificate.js";
import { verifyDataGroupHashes } from "./internal/data-groups.js";
import { verifyCmsSignedData } from "./internal/cms.js";
import { describe } from "./internal/errors.js";
import type {
  PassiveVerificationInput,
  PassiveVerificationResult,
  DataGroupVerificationResult,
} from "./public-types.js";

/**
 * Verify an eMRTD passive authentication bundle: SOD CMS signature + DSC chain
 * to a caller-supplied CSCA + per-DG hash recomputation against the SOD's
 * signed values.
 */
export async function verifyPassive(
  input: PassiveVerificationInput,
): Promise<PassiveVerificationResult> {
  const errors: string[] = [];
  let signerCommonName: string | null = null;
  let signedAt: Date | null = null;
  let dataGroupResults: DataGroupVerificationResult[] = [];

  let sodContents;
  try {
    sodContents = parseSod(input.rawSod);
  } catch (e) {
    errors.push(describe("SOD parse failed", e));
    return {
      valid: false,
      errors,
      signerCommonName,
      signedAt,
      dataGroupResults,
    };
  }

  signerCommonName = commonNameOf(sodContents.dsc);

  const cmsOutcome = await verifyCmsSignedData(sodContents.signedData);
  signedAt = cmsOutcome.signedAt;
  if (!cmsOutcome.valid && cmsOutcome.error) {
    errors.push(cmsOutcome.error);
  }

  let chainValid = false;
  try {
    const anchors = parseAnchors(input.trustAnchors);
    const chainResult = await verifyCertificateChain(sodContents.dsc, anchors);
    chainValid = chainResult.valid;
    if (!chainResult.valid && chainResult.error) {
      errors.push(`Certificate chain: ${chainResult.error}`);
    }
  } catch (e) {
    errors.push(describe("Certificate chain error", e));
  }

  try {
    const providedDgs = new Map<number, Uint8Array>();
    for (const [key, bytes] of Object.entries(input.dataGroups)) {
      const n = Number(key);
      if (Number.isFinite(n) && bytes) providedDgs.set(n, bytes);
    }
    dataGroupResults = verifyDataGroupHashes(
      sodContents.hashAlgorithmOid,
      sodContents.dataGroupHashes,
      providedDgs,
    );
    for (const r of dataGroupResults) {
      if (!r.valid && r.error) errors.push(r.error);
    }
  } catch (e) {
    errors.push(describe("Hash verification error", e));
  }

  const allDgsValid =
    dataGroupResults.length > 0 && dataGroupResults.every((r) => r.valid);
  const valid = cmsOutcome.valid && chainValid && allDgsValid;

  return {
    valid,
    errors,
    signerCommonName,
    signedAt,
    dataGroupResults,
  };
}
