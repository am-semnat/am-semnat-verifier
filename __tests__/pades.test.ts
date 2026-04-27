import { describe, expect, it } from "vitest";
import { verifyPadesSignatures } from "../src/index.js";
import { buildPadesFixture } from "./fixtures/generate.js";

describe("verifyPadesSignatures", () => {
  it("returns valid:true for a single happy-path signature", async () => {
    const fixture = await buildPadesFixture({ numSignatures: 1 });
    const results = await verifyPadesSignatures({
      pdf: fixture.pdf,
      trustAnchors: fixture.trustAnchors,
    });
    expect(results).toHaveLength(1);
    const [sig] = results;
    expect(sig?.valid).toBe(true);
    expect(sig?.errors).toEqual([]);
    expect(sig?.signerCommonName).toBe("POPESCU ION");
    expect(sig?.fieldName).toBe("Signature1");
    expect(sig?.coversWholeDocument).toBe(true);
    expect(sig?.signedAt).toBeInstanceOf(Date);
  });

  it("validates both signatures in a two-signer group sign", async () => {
    const fixture = await buildPadesFixture({ numSignatures: 2 });
    const results = await verifyPadesSignatures({
      pdf: fixture.pdf,
      trustAnchors: fixture.trustAnchors,
    });
    expect(results).toHaveLength(2);
    expect(results[0]?.valid).toBe(true);
    expect(results[1]?.valid).toBe(true);
    expect(results[0]?.coversWholeDocument).toBe(false);
    expect(results[1]?.coversWholeDocument).toBe(true);
    expect(results[0]?.fieldName).toBe("Signature1");
    expect(results[1]?.fieldName).toBe("Signature2");
  });

  it("flags coversWholeDocument:false when the PDF is appended after signing (and CMS digest still matches the original byte range)", async () => {
    const fixture = await buildPadesFixture({
      numSignatures: 1,
      tamperAfterSign: true,
    });
    const results = await verifyPadesSignatures({
      pdf: fixture.pdf,
      trustAnchors: fixture.trustAnchors,
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.coversWholeDocument).toBe(false);
    // CMS itself is still valid because the byte range was fixed at signing
    // time — `valid` stays true. The consumer's job is to combine
    // `valid && coversWholeDocument` for "whole document is signed".
    expect(results[0]?.valid).toBe(true);
  });

  it("rejects a wrong DGEP root anchor", async () => {
    const fixture = await buildPadesFixture({
      numSignatures: 1,
      wrongAnchor: true,
    });
    const results = await verifyPadesSignatures({
      pdf: fixture.pdf,
      trustAnchors: fixture.trustAnchors,
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.valid).toBe(false);
    expect(results[0]?.errors.some((e) => /chain/i.test(e))).toBe(true);
  });

  it("rejects an expired citizen certificate", async () => {
    const fixture = await buildPadesFixture({
      numSignatures: 1,
      expiredCitizen: true,
    });
    const results = await verifyPadesSignatures({
      pdf: fixture.pdf,
      trustAnchors: fixture.trustAnchors,
    });
    expect(results).toHaveLength(1);
    expect(results[0]?.valid).toBe(false);
    expect(results[0]?.errors.some((e) => /expired|not yet valid/i.test(e))).toBe(
      true,
    );
  });

  it("returns [] for an unsigned PDF", async () => {
    const fixture = await buildPadesFixture({ unsigned: true });
    const results = await verifyPadesSignatures({
      pdf: fixture.pdf,
      trustAnchors: fixture.trustAnchors,
    });
    expect(results).toEqual([]);
  });
});
