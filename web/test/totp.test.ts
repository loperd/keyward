import { describe, expect, it } from "vitest";
import { isWebError } from "../src/backend/errors";
import { parseTotp, seedBytes, totpAt } from "../src/backend/totp";

const SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

// RFC 6238, appendix B: eight digits, period 30.
const VECTORS: [number, string, string, string][] = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"],
];

const at = (field: string, t: number) => totpAt(parseTotp(field), t * 1000);

describe("TOTP", () => {
  it("matches RFC 6238 for SHA-1, SHA-256 and SHA-512", async () => {
    for (const [t, s1, s256, s512] of VECTORS) {
      expect((await at(`otpauth://totp/x?secret=${SHA1}&digits=8`, t)).code).toBe(s1);
      expect((await at(`otpauth://totp/x?secret=${SHA256}&digits=8&algorithm=SHA256`, t)).code).toBe(s256);
      expect((await at(`otpauth://totp/x?secret=${SHA512}&digits=8&algorithm=SHA512`, t)).code).toBe(s512);
    }
  });

  it("takes a bare base32 seed as SHA-1, six digits, thirty seconds", async () => {
    const r = await at(SHA1, 59);
    expect(r).toEqual({ code: "287082", period: 30, remaining: 1 });
  });

  it("reads the period from the link", async () => {
    const r = await at(`otpauth://totp/Example:a@b.c?secret=${SHA1}&period=60&issuer=Example`, 59);
    expect(r.period).toBe(60);
    expect(r.remaining).toBe(1);
  });

  // Computed by an independent Python implementation of Steam Guard.
  it("makes Steam Guard's five letters", async () => {
    expect((await at(`steam://${SHA1}`, 59)).code).toBe("PV9M4");
    expect((await at(`steam://${SHA1}`, 1234567890)).code).toBe("VHHQY");
    expect((await at(`otpauth://totp/Steam:me?secret=${SHA1}&encoder=steam`, 59)).code).toBe("PV9M4");
  });

  it("reads any spelling of the same seed", () => {
    const canon = Array.from(seedBytes("JBSWY3DPEHPK3PXP"));
    for (const s of ["jbswy3dp ehpk3pxp", "JBSW-Y3DP-EHPK-3PXP", "JBSWY3DPEHPK3PXP===", " JBSWY3DPEHPK3PXP ", "secret=JBSWY3DPEHPK3PXP&issuer=x"]) {
      expect(Array.from(seedBytes(s)), s).toEqual(canon);
    }
    expect(Array.from(seedBytes("00112233445566778899aabbccddeeff"))).toEqual(Array.from({ length: 16 }, (_, i) => i * 17));
  });

  it("refuses a code saved in place of the seed, and never says the seed", () => {
    const codeOf = (f: () => unknown) => {
      try {
        f();
      } catch (e) {
        if (isWebError(e)) return e;
      }
      return null;
    };
    expect(codeOf(() => parseTotp("482913"))?.code).toBe("err.totpLooksLikeCode");
    const e = codeOf(() => parseTotp("paste me later?"));
    expect(e?.code).toBe("err.totpSeedBadAlphabet");
    expect(JSON.stringify(e?.args)).not.toMatch(/paste|later/);
    expect(codeOf(() => parseTotp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"))?.code).toBe("err.totpLinkUnreadable");
    expect(codeOf(() => parseTotp("   "))?.code).toBe("err.totpSeedEmpty");
  });

  it("wipes the seed once the code is made", async () => {
    const p = parseTotp(SHA1);
    await totpAt(p, 59_000);
    expect(p.secret.every((b) => b === 0)).toBe(true);
  });
});
