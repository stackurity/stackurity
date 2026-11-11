import { test } from "node:test";
import assert from "node:assert/strict";
import { DENSITY_KEY, densityClass, parseDensity, readDensity, writeDensity, type DensityStorage } from "./tableDensity.ts";

function memory(): DensityStorage & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

const throwing: DensityStorage = {
  getItem: () => {
    throw new Error("SecurityError");
  },
  setItem: () => {
    throw new Error("QuotaExceededError");
  },
  removeItem: () => {
    throw new Error("SecurityError");
  },
};

test("anything but comfortable or compact reads as default", () => {
  assert.equal(parseDensity("compact"), "compact");
  assert.equal(parseDensity("comfortable"), "comfortable");
  for (const v of [null, undefined, "", "default", "dense", "COMPACT", 3]) assert.equal(parseDensity(v), "default");
});

test("a choice is remembered and read back; default removes the key", () => {
  const s = memory();
  assert.equal(readDensity(s), "default");
  assert.equal(writeDensity(s, "compact"), true);
  assert.equal(s.data.get(DENSITY_KEY), "compact");
  assert.equal(readDensity(s), "compact");
  assert.equal(writeDensity(s, "default"), true);
  assert.equal(s.data.has(DENSITY_KEY), false);
  assert.equal(readDensity(s), "default");
});

test("storage that is missing or throws never breaks the table", () => {
  assert.equal(readDensity(null), "default");
  assert.equal(readDensity(undefined), "default");
  assert.equal(readDensity(throwing), "default");
  assert.equal(writeDensity(null, "compact"), false);
  assert.equal(writeDensity(throwing, "compact"), false);
  assert.equal(writeDensity(throwing, "default"), false);
});

test("default adds no class, so tables look as they always did", () => {
  assert.equal(densityClass("default"), "");
  assert.equal(densityClass("compact"), "density-compact");
  assert.equal(densityClass("comfortable"), "density-comfortable");
});
