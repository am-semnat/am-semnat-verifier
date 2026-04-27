import * as pkijs from "pkijs";

// pkijs needs WebCrypto wired in once at module load — Node 20+ exposes it
// globally as `globalThis.crypto` (subset implementing SubtleCrypto). Without
// this, signedData.verify() silently throws "no engine" on the first call.
const cryptoEngine = (globalThis as unknown as { crypto?: Crypto }).crypto;
if (cryptoEngine?.subtle) {
  pkijs.setEngine(
    "node-webcrypto",
    new pkijs.CryptoEngine({
      crypto: cryptoEngine,
      subtle: cryptoEngine.subtle,
      name: "node-webcrypto",
    }),
  );
}

export { verifyPassive } from "./passive.js";
export { verifyPadesSignatures } from "./pades.js";

export type {
  DerBytes,
  PassiveVerificationInput,
  PassiveVerificationResult,
  DataGroupVerificationResult,
  PadesVerificationInput,
  PadesVerificationResult,
} from "./public-types.js";
