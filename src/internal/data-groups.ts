import { createHash } from "node:crypto";
import { hashAlgorithmFromOid } from "./certificate.js";
import type { DataGroupVerificationResult } from "../public-types.js";

const NODE_HASH_MAP: Record<string, string> = {
  "SHA-1": "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
};

function computeHash(data: Uint8Array, algorithm: string): Uint8Array {
  const nodeAlg = NODE_HASH_MAP[algorithm];
  if (!nodeAlg) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  return new Uint8Array(createHash(nodeAlg).update(data).digest());
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= (a[i] as number) ^ (b[i] as number);
  }
  return result === 0;
}

/**
 * Verify that the provided raw data group bytes match the hashes signed in the
 * SOD's LDS Security Object. Returns a per-DG outcome list covering every DG
 * the SOD claims a hash for — DGs the caller didn't supply are reported as
 * `valid: false` so the caller can spot omissions.
 */
export function verifyDataGroupHashes(
  hashAlgorithmOid: string,
  expectedHashes: Map<number, Uint8Array>,
  providedDgs: Map<number, Uint8Array>,
): DataGroupVerificationResult[] {
  const algorithm = hashAlgorithmFromOid(hashAlgorithmOid);
  const results: DataGroupVerificationResult[] = [];

  const dgNumbers = new Set<number>([
    ...expectedHashes.keys(),
    ...providedDgs.keys(),
  ]);
  const ordered = [...dgNumbers].sort((a, b) => a - b);

  for (const dgNumber of ordered) {
    const expectedHash = expectedHashes.get(dgNumber);
    const provided = providedDgs.get(dgNumber);

    if (!expectedHash) {
      results.push({
        dgNumber,
        valid: false,
        error: `DG${dgNumber} provided but not present in SOD`,
      });
      continue;
    }
    if (!provided) {
      results.push({
        dgNumber,
        valid: false,
        error: `DG${dgNumber} hash present in SOD but no bytes provided`,
      });
      continue;
    }

    try {
      const computed = computeHash(provided, algorithm);
      if (constantTimeEqual(computed, expectedHash)) {
        results.push({ dgNumber, valid: true });
      } else {
        results.push({
          dgNumber,
          valid: false,
          error: `DG${dgNumber} hash mismatch`,
        });
      }
    } catch (e) {
      results.push({
        dgNumber,
        valid: false,
        error: `Failed to verify DG${dgNumber}: ${e instanceof Error ? e.message : String(e)}`,
      });
    }
  }

  return results;
}
