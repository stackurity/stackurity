import { test } from "node:test";
import assert from "node:assert/strict";
import { b64urlToBuffer, bufferToB64url, creationOptions, requestOptions } from "./webauthnCodec.ts";

test("base64url round trip, without padding", () => {
  for (const bytes of [[], [0], [0xfb, 0xff], [1, 2, 3, 4, 5], Array.from({ length: 64 }, (_, i) => (i * 37) % 256)]) {
    const s = bufferToB64url(new Uint8Array(bytes).buffer);
    assert.ok(!/[+/=]/.test(s), s);
    assert.deepEqual([...new Uint8Array(b64urlToBuffer(s))], bytes);
  }
  assert.equal(bufferToB64url(new Uint8Array([0xfb, 0xff]).buffer), "-_8");
});

test("creation options decode the challenge, user id and excluded credentials", () => {
  const o = creationOptions({
    publicKey: {
      challenge: "AQID",
      rp: { id: "stk.example", name: "Stackurity" },
      user: { id: "BAU", name: "ann@x.io", displayName: "Ann" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ type: "public-key", id: "Bgc", transports: ["usb"] }],
    },
  });
  const pk = o.publicKey!;
  assert.deepEqual([...new Uint8Array(pk.challenge as ArrayBuffer)], [1, 2, 3]);
  assert.deepEqual([...new Uint8Array(pk.user.id as ArrayBuffer)], [4, 5]);
  assert.deepEqual([...new Uint8Array(pk.excludeCredentials![0].id as ArrayBuffer)], [6, 7]);
  assert.equal(pk.rp.id, "stk.example");
});

test("request options without allowCredentials stay discoverable", () => {
  const o = requestOptions({ publicKey: { challenge: "AQID", rpId: "stk.example", userVerification: "required" } });
  assert.equal(o.publicKey!.allowCredentials, undefined);
  assert.equal(o.publicKey!.userVerification, "required");
});
