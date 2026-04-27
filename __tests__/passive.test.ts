import { describe, expect, it } from "vitest";
import { verifyPassive } from "../src/index.js";
import { buildPassiveFixture } from "./fixtures/generate.js";

describe("verifyPassive", () => {
  it("returns valid:true for a well-formed bundle", async () => {
    const fixture = await buildPassiveFixture();
    const result = await verifyPassive({
      rawSod: fixture.rawSod,
      dataGroups: fixture.dataGroups,
      trustAnchors: fixture.trustAnchors,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.signerCommonName).toBe("Synthetic DSC");
    expect(result.signedAt).toBeInstanceOf(Date);
    expect(result.dataGroupResults).toHaveLength(3);
    expect(result.dataGroupResults.every((r) => r.valid)).toBe(true);
  });

  it("flags a tampered DG2 without affecting the CMS signature check", async () => {
    const fixture = await buildPassiveFixture({ tamperDg: 2 });
    const result = await verifyPassive({
      rawSod: fixture.rawSod,
      dataGroups: fixture.dataGroups,
      trustAnchors: fixture.trustAnchors,
    });
    expect(result.valid).toBe(false);
    const dg2 = result.dataGroupResults.find((r) => r.dgNumber === 2);
    expect(dg2?.valid).toBe(false);
    expect(dg2?.error).toMatch(/DG2 hash mismatch/);
    const dg1 = result.dataGroupResults.find((r) => r.dgNumber === 1);
    expect(dg1?.valid).toBe(true);
  });

  it("rejects a wrong CSCA trust anchor", async () => {
    const fixture = await buildPassiveFixture({ wrongAnchor: true });
    const result = await verifyPassive({
      rawSod: fixture.rawSod,
      dataGroups: fixture.dataGroups,
      trustAnchors: fixture.trustAnchors,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /chain/i.test(e))).toBe(true);
  });

  it("rejects an expired DSC", async () => {
    const fixture = await buildPassiveFixture({ expireDsc: true });
    const result = await verifyPassive({
      rawSod: fixture.rawSod,
      dataGroups: fixture.dataGroups,
      trustAnchors: fixture.trustAnchors,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /expired|not yet valid/i.test(e))).toBe(
      true,
    );
  });

  it("flags a DG present in the SOD but missing from the input", async () => {
    const fixture = await buildPassiveFixture({ dropDg: 14 });
    const result = await verifyPassive({
      rawSod: fixture.rawSod,
      dataGroups: fixture.dataGroups,
      trustAnchors: fixture.trustAnchors,
    });
    expect(result.valid).toBe(false);
    const dg14 = result.dataGroupResults.find((r) => r.dgNumber === 14);
    expect(dg14?.valid).toBe(false);
    expect(dg14?.error).toMatch(/no bytes provided/);
  });

  it("returns a single SOD-parse error for malformed bytes", async () => {
    const result = await verifyPassive({
      rawSod: new Uint8Array([0x00, 0x01, 0x02]),
      dataGroups: {},
      trustAnchors: [],
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/SOD parse failed/);
    expect(result.dataGroupResults).toEqual([]);
  });
});
