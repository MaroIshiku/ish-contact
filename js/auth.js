import { base64ToBytes, bytesToBase64, decryptStringWithPin, decryptStringWithRawKey, encryptStringWithPin, encryptStringWithRawKey, randomBytes } from './crypto.js';

const PIN_KEY = 'dv2.pinWrappedPassword';
const PASSKEY_META_KEY = 'dv2.passkeyMeta';
const PASSKEY_BLOB_KEY = 'dv2.passkeyWrappedPassword';

export const Auth = {
  hasPin() { return Boolean(localStorage.getItem(PIN_KEY)); },
  async savePin(pin, masterPassword) {
    assertPin(pin);
    localStorage.setItem(PIN_KEY, await encryptStringWithPin(masterPassword, pin));
  },
  async passwordFromPin(pin) {
    assertPin(pin);
    const blob = localStorage.getItem(PIN_KEY);
    if (!blob) throw new Error('Keine PIN eingerichtet.');
    return decryptStringWithPin(blob, pin);
  },
  clearPin() { localStorage.removeItem(PIN_KEY); },

  passkeyAvailable() { return Boolean(window.PublicKeyCredential); },
  hasPasskey() { return Boolean(localStorage.getItem(PASSKEY_META_KEY) && localStorage.getItem(PASSKEY_BLOB_KEY)); },

  async setupPasskey(masterPassword) {
    if (!Auth.passkeyAvailable()) throw new Error('Passkeys werden auf diesem Gerät nicht unterstützt.');
    const userId = randomBytes(16);
    const challenge = randomBytes(32);
    const prfSalt = randomBytes(32);
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: 'Digitale Visitenkarte v2' },
        user: { id: userId, name: 'single-user@local', displayName: 'Digitale Visitenkarte' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
        timeout: 60000,
        attestation: 'none',
        extensions: { prf: { eval: { first: prfSalt } } }
      }
    });
    const ext = credential.getClientExtensionResults?.() || {};
    const prfResult = ext.prf?.results?.first;
    if (!prfResult) {
      localStorage.setItem(PASSKEY_META_KEY, JSON.stringify({ id: bytesToBase64(new Uint8Array(credential.rawId)), prf: false }));
      throw new Error('Passkey wurde registriert, aber dein Browser liefert keinen PRF-Schlüssel. Für sicheren Schnell-Login bitte PIN nutzen.');
    }
    const rawKey = new Uint8Array(prfResult).slice(0, 32);
    localStorage.setItem(PASSKEY_META_KEY, JSON.stringify({ id: bytesToBase64(new Uint8Array(credential.rawId)), prf: true, salt: bytesToBase64(prfSalt) }));
    localStorage.setItem(PASSKEY_BLOB_KEY, await encryptStringWithRawKey(masterPassword, rawKey));
  },

  async passwordFromPasskey() {
    const meta = JSON.parse(localStorage.getItem(PASSKEY_META_KEY) || 'null');
    const blob = localStorage.getItem(PASSKEY_BLOB_KEY);
    if (!meta?.prf || !blob) throw new Error('Kein nutzbarer Passkey-Schnelllogin eingerichtet.');
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        allowCredentials: [{ type: 'public-key', id: base64ToBytes(meta.id) }],
        userVerification: 'required',
        timeout: 60000,
        extensions: { prf: { eval: { first: base64ToBytes(meta.salt) } } }
      }
    });
    const prfResult = credential.getClientExtensionResults?.().prf?.results?.first;
    if (!prfResult) throw new Error('Dieser Passkey hat keinen PRF-Schlüssel zurückgegeben.');
    return decryptStringWithRawKey(blob, new Uint8Array(prfResult).slice(0, 32));
  },

  clearPasskey() { localStorage.removeItem(PASSKEY_META_KEY); localStorage.removeItem(PASSKEY_BLOB_KEY); },

  startAutoLock(onLock) {
    let timer = 0;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(onLock, 5 * 60 * 1000);
    };
    ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(event => addEventListener(event, reset, { passive: true }));
    reset();
    return () => clearTimeout(timer);
  }
};

function assertPin(pin) {
  if (!/^\d{4,6}$/.test(pin)) throw new Error('PIN muss 4–6 Ziffern haben.');
}
