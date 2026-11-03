/**
 * Passkeys and security keys in the browser (WebAuthn). The server sends
 * the options for navigator.credentials.create() or .get() as JSON with
 * binary values in base64url ({"publicKey": {...}}); this turns them into
 * what the browser takes, and the browser's answer back into JSON.
 * No library: the conversions are small and the CSP allows no other script.
 */
import { ApiError } from "./api";
import { bufferToB64url, creationOptions, requestOptions } from "./webauthnCodec";

/** Whether this browser can use passkeys at all. */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

/** A credential from the browser as the JSON the server reads. */
export function credentialJSON(cred: PublicKeyCredential): Record<string, unknown> {
  const r = cred.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const response: Record<string, unknown> = { clientDataJSON: bufferToB64url(r.clientDataJSON) };
  if ("attestationObject" in r && r.attestationObject) {
    response.attestationObject = bufferToB64url(r.attestationObject);
    response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  }
  if ("authenticatorData" in r && r.authenticatorData) {
    response.authenticatorData = bufferToB64url(r.authenticatorData);
    response.signature = bufferToB64url(r.signature);
    if (r.userHandle) response.userHandle = bufferToB64url(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

// Browser errors become ApiErrors (status 0) so the pages show them as any
// other: the prompt closed or timed out, or a key already registered.
function wrap(e: unknown): never {
  if (e instanceof ApiError) throw e;
  if (e instanceof DOMException && (e.name === "NotAllowedError" || e.name === "AbortError")) {
    throw new ApiError(0, "passkey_cancelled", "The passkey prompt was closed or timed out. Try again.");
  }
  if (e instanceof DOMException && e.name === "InvalidStateError") {
    throw new ApiError(0, "passkey_registered", "This passkey or security key is already registered to your account.");
  }
  throw new ApiError(0, "passkey_error", e instanceof Error ? e.message : String(e));
}

/** Asks the browser to make a passkey for the server's options. */
export async function createPasskey(options: unknown): Promise<Record<string, unknown>> {
  try {
    const cred = (await navigator.credentials.create(creationOptions(options))) as PublicKeyCredential | null;
    if (!cred) throw new ApiError(0, "passkey_cancelled", "No passkey was made.");
    return credentialJSON(cred);
  } catch (e) {
    return wrap(e);
  }
}

/** Asks the browser to sign the server's challenge with a passkey. */
export async function getPasskey(options: unknown): Promise<Record<string, unknown>> {
  try {
    const cred = (await navigator.credentials.get(requestOptions(options))) as PublicKeyCredential | null;
    if (!cred) throw new ApiError(0, "passkey_cancelled", "No passkey was chosen.");
    return credentialJSON(cred);
  } catch (e) {
    return wrap(e);
  }
}
