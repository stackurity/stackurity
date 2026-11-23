/** The passkey offer after a password sign-in (pages/PasskeyOffer.tsx). */

/** "Not now" keeps the offer away on this browser for this long. */
const SNOOZE_DAYS = 30;
const snoozeKey = (userId: number) => `stackurity.passkeyOffer.${userId}`;

/** Whether this person said "Not now" here recently (browser storage may be off). */
export function passkeyOfferSnoozed(userId: number): boolean {
  try {
    const at = Number(window.localStorage.getItem(snoozeKey(userId)));
    return at > 0 && Date.now() - at < SNOOZE_DAYS * 86_400_000;
  } catch {
    return false;
  }
}

export function snoozePasskeyOffer(userId: number) {
  try {
    window.localStorage.setItem(snoozeKey(userId), String(Date.now()));
  } catch {
    // Without storage the offer comes back only after the next password sign-in.
  }
}

/** What this device unlocks a passkey with, for the heading and a default name. */
export function deviceUnlock(ua: string = navigator.userAgent): { method: string; name: string } {
  if (/iPhone/.test(ua)) return { method: "Face ID or Touch ID", name: "iPhone" };
  if (/iPad/.test(ua)) return { method: "Face ID or Touch ID", name: "iPad" };
  if (/Android/.test(ua)) return { method: "your fingerprint or face", name: "Android phone" };
  if (/Macintosh|Mac OS X/.test(ua)) return { method: "Touch ID", name: "Mac Touch ID" };
  if (/Windows/.test(ua)) return { method: "Windows Hello", name: "Windows Hello" };
  return { method: "your fingerprint, face or device PIN", name: "This device" };
}
