/**
 * Conversions between the JSON a server sends for WebAuthn (binary values
 * in base64url) and what navigator.credentials takes. No imports, so the
 * tests run them under Node.
 */

export function b64urlToBuffer(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

export function bufferToB64url(buf: ArrayBuffer | ArrayBufferView | null | undefined): string {
  if (!buf) return "";
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface JSONDescriptor {
  id: string;
  type: string;
  transports?: string[];
}

interface CreationJSON {
  publicKey: Record<string, unknown> & {
    challenge: string;
    user: Record<string, unknown> & { id: string };
    excludeCredentials?: JSONDescriptor[];
  };
}

interface RequestJSON {
  publicKey: Record<string, unknown> & {
    challenge: string;
    allowCredentials?: JSONDescriptor[];
  };
  mediation?: string;
}

function descriptors(list: JSONDescriptor[] | undefined): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((d) => ({ ...d, type: "public-key", id: b64urlToBuffer(d.id), transports: d.transports as AuthenticatorTransport[] | undefined }));
}

/** The options from a server's registration step, for navigator.credentials.create(). */
export function creationOptions(json: unknown): CredentialCreationOptions {
  const o = json as CreationJSON;
  const pk = o.publicKey;
  return {
    publicKey: {
      ...(pk as unknown as PublicKeyCredentialCreationOptions),
      challenge: b64urlToBuffer(pk.challenge),
      user: { ...(pk.user as unknown as PublicKeyCredentialUserEntity), id: b64urlToBuffer(pk.user.id) },
      excludeCredentials: descriptors(pk.excludeCredentials),
    },
  };
}

/** The options from a server's sign-in step, for navigator.credentials.get(). */
export function requestOptions(json: unknown): CredentialRequestOptions {
  const o = json as RequestJSON;
  const pk = o.publicKey;
  return {
    publicKey: {
      ...(pk as unknown as PublicKeyCredentialRequestOptions),
      challenge: b64urlToBuffer(pk.challenge),
      allowCredentials: descriptors(pk.allowCredentials),
    },
  };
}
