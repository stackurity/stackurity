import { test } from "node:test";
import assert from "node:assert/strict";
import { deviceUnlock, passkeyOfferSnoozed, snoozePasskeyOffer } from "./passkeyOffer.ts";

test("deviceUnlock names the device's unlock", () => {
  const mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15";
  const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1";
  const android = "Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36";
  const windows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36";
  assert.deepEqual(deviceUnlock(mac), { method: "Touch ID", name: "Mac Touch ID" });
  // An iPhone's user agent says "like Mac OS X": it must not read as a Mac.
  assert.deepEqual(deviceUnlock(iphone), { method: "Face ID or Touch ID", name: "iPhone" });
  assert.equal(deviceUnlock(android).name, "Android phone");
  assert.equal(deviceUnlock(windows).method, "Windows Hello");
  assert.equal(deviceUnlock("curl/8").name, "This device");
});

test("Not now snoozes the offer per person, and no storage means no snooze", () => {
  const store = new Map<string, string>();
  (globalThis as { window?: unknown }).window = {
    localStorage: { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) },
  };
  assert.equal(passkeyOfferSnoozed(7), false);
  snoozePasskeyOffer(7);
  assert.equal(passkeyOfferSnoozed(7), true);
  assert.equal(passkeyOfferSnoozed(8), false);
  store.set("stackurity.passkeyOffer.7", String(Date.now() - 31 * 86_400_000));
  assert.equal(passkeyOfferSnoozed(7), false);
  (globalThis as { window?: unknown }).window = {
    get localStorage(): Storage {
      throw new Error("blocked");
    },
  };
  assert.equal(passkeyOfferSnoozed(7), false);
  assert.doesNotThrow(() => snoozePasskeyOffer(7));
  delete (globalThis as { window?: unknown }).window;
});
