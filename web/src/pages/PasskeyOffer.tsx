import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { ErrorBox, Loading } from "../components/ui";
import { createPasskey, passkeysSupported } from "../webauthn";
import { RecoveryCodes } from "./TwoFactor";
import { deviceUnlock, snoozePasskeyOffer } from "../passkeyOffer";

/**
 * Shown once, right after a password sign-in, to someone without a passkey
 * (GET /auth/me passkey_offer): add one so the next sign-in is a fingerprint
 * or a face. The server skips asking for the password again for a few
 * minutes after it was typed. Devices without a built-in authenticator are
 * not asked (a security key is still added under Your account).
 */
export function PasskeyOfferPage({ onDone }: { onDone: () => void }) {
  const { me, refresh } = useAuth();
  const userId = me?.user?.id ?? 0;
  const unlock = deviceUnlock();
  const [platform, setPlatform] = useState<boolean | null>(null);
  const [name, setName] = useState(unlock.name);
  const [codes, setCodes] = useState<string[] | null>(null);
  const act = useAction();

  useEffect(() => {
    let live = true;
    const check = passkeysSupported() && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
      ? PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false)
      : Promise.resolve(false);
    void check.then((ok) => {
      if (!live) return;
      setPlatform(ok);
      if (!ok) onDone();
    });
    return () => {
      live = false;
    };
  }, [onDone]);

  const finish = () => {
    onDone();
    void refresh();
  };
  const notNow = () => {
    snoozePasskeyOffer(userId);
    onDone();
  };
  const add = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(async () => {
      // No password: the server accepts none just after a password sign-in.
      const begin = await api.post<{ options: unknown }>("/auth/mfa/passkeys/begin", {});
      const credential = await createPasskey(begin.options);
      return api.post<{ recovery_codes: string[] | null }>("/auth/mfa/passkeys/finish", { name: name.trim(), credential });
    });
    if (!r) return;
    if (r.recovery_codes) setCodes(r.recovery_codes);
    else finish();
  };

  if (platform !== true) {
    return (
      <div className="center-screen">
        <Loading />
      </div>
    );
  }
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        {codes ? (
          <>
            <h1 className="auth-title">Passkey added</h1>
            <p>Next time, choose Sign in with a passkey and use {unlock.method}.</p>
            <RecoveryCodes codes={codes} onDone={finish} />
          </>
        ) : (
          <form className="form" onSubmit={add} aria-labelledby="pk-offer-title">
            <h1 id="pk-offer-title" className="auth-title">
              Sign in with {unlock.method} next time
            </h1>
            <p>
              Add a passkey and skip the password: choose <strong>Sign in with a passkey</strong> and use {unlock.method}. It cannot be phished or
              reused on another site.
            </p>
            <ErrorBox error={act.error} title="Could not add the passkey" />
            <div className="field">
              <label htmlFor="pk-offer-name">Name</label>
              <input id="pk-offer-name" required maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
              <p className="hint">So you can tell your passkeys apart. Your browser then asks where to save it; your other sessions are signed out.</p>
            </div>
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={act.pending}>
                {act.pending ? "Waiting for your passkey…" : "Add passkey"}
              </button>
              <button type="button" className="btn" onClick={notNow} disabled={act.pending}>
                Not now
              </button>
            </div>
            <p className="hint">You can add or remove passkeys any time under Your account → Two-factor methods.</p>
          </form>
        )}
      </div>
    </div>
  );
}
