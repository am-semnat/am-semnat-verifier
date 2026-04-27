import { describe, expect, it } from "vitest";
import { extractSignatures } from "../src/internal/pdf-signatures.js";
import { buildPadesFixture } from "./fixtures/generate.js";

describe("extractSignatures", () => {
  it("locates a single PAdES signature dict", async () => {
    const fixture = await buildPadesFixture({ numSignatures: 1 });
    const sigs = extractSignatures(fixture.pdf);
    expect(sigs).toHaveLength(1);
    const [sig] = sigs;
    expect(sig?.signatureIndex).toBe(0);
    expect(sig?.fieldName).toBe("Signature1");
    expect(sig?.subFilter).toBe("ETSI.CAdES.detached");
    expect(sig?.coversWholeDocument).toBe(true);
    // ByteRange numbers should partition the PDF around the /Contents hex.
    const [a, b, c, d] = sig!.byteRange;
    expect(a).toBe(0);
    expect(b).toBeGreaterThan(0);
    expect(c).toBeGreaterThan(b);
    expect(c + d).toBeGreaterThanOrEqual(fixture.pdf.length - 2);
    expect(sig?.contents.length).toBeGreaterThan(0);
  });

  it("returns multi-sig signatures in document order", async () => {
    const fixture = await buildPadesFixture({ numSignatures: 2 });
    const sigs = extractSignatures(fixture.pdf);
    expect(sigs).toHaveLength(2);
    expect(sigs[0]?.signatureIndex).toBe(0);
    expect(sigs[1]?.signatureIndex).toBe(1);
    expect(sigs[0]?.fieldName).toBe("Signature1");
    expect(sigs[1]?.fieldName).toBe("Signature2");
    // Earlier signature does NOT cover the appended incremental update.
    expect(sigs[0]?.coversWholeDocument).toBe(false);
    expect(sigs[1]?.coversWholeDocument).toBe(true);
  });

  it("flags coversWholeDocument:false when bytes are appended after the last signature", async () => {
    const fixture = await buildPadesFixture({
      numSignatures: 1,
      tamperAfterSign: true,
    });
    const sigs = extractSignatures(fixture.pdf);
    expect(sigs).toHaveLength(1);
    expect(sigs[0]?.coversWholeDocument).toBe(false);
  });
});
