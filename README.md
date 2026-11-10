# WHMCS Passkey 2FA

An open-source two-factor authentication module for WHMCS that uses
**passkeys and security keys** (WebAuthn / FIDO2) as the second factor:
Touch ID, Face ID, Windows Hello, Android, password-manager passkeys and
hardware keys such as YubiKey.

It plugs into the standard WHMCS two-factor system, so it works for both
clients and admins, next to the built-in Time Based Tokens. Plain PHP, no
encoded files, no licensing calls, no third-party service, no Composer
dependencies.

## Why

WHMCS ships three second factors: time based codes, Duo and YubiKey OTP. None
of them is WebAuthn, so a code can still be typed into a look-alike site. A
passkey is bound to your domain by the browser and cannot be phished that way,
and there is nothing to type.

A free passkey module we reviewed issues a challenge but never checks the
signature that comes back, which makes it a login button, not a second
factor. This one verifies every response on the server:

- the challenge is random, single use, short lived and bound to the session
- the origin must be your WHMCS domain, over HTTPS
- the relying party ID hash and the user-presence flag are checked
- the signature is verified against the stored public key (ES256 or RS256)
- the signature counter must advance when the authenticator keeps one, which
  catches cloned hardware keys
- a response is only accepted from a passkey registered to the user logging in

The whole verifier is one file of under 300 lines:
[`lib/WebAuthn.php`](modules/security/webauthn/lib/WebAuthn.php).

## Features

- Second factor for clients and admins through the normal WHMCS 2FA screens
- Several passkeys per user (for example a phone and a hardware key), added
  during setup
- Starts the passkey prompt automatically at login, no extra click
- Optional "require user verification" (biometric or PIN on every sign-in)
- Configurable relying party ID, so passkeys can survive a move to another
  subdomain
- WHMCS backup codes keep working as the recovery path
- No extra HTTP endpoint and no database table: the result travels in the
  form WHMCS already renders, and credentials live in the user's own WHMCS
  two-factor settings
- English and Bulgarian interface text, easy to extend

## Requirements

- WHMCS 9.x (developed and run on 9.1; 8.x uses the same module interface
  but is untested)
- PHP 8.1+ with the `openssl` extension
- WHMCS served over HTTPS
- A current browser (Chrome/Edge 85+, Safari 16+, Firefox 119+)

## Install / update

Copy `modules/security/webauthn` into your WHMCS installation. One-liner
(run from anywhere, point it at your WHMCS document root):

```sh
curl -fsSL https://github.com/theorigamicorporation/whmcs-passkey-2fa/releases/latest/download/whmcs-passkey-2fa.tgz \
  | tar -xz --strip-components=1 -C /path/to/whmcs whmcs-passkey-2fa/modules
```

or from a checkout: `DOCROOT=/path/to/whmcs ./deploy/deploy.sh`.

Then in the admin area open **Configuration > System Settings > Two-Factor
Authentication**, activate **Passkey / Security Key** and enable it for
clients, staff or both.

Users turn it on under **Security Settings** (clients) or **My Account**
(admins): choose the passkey method, press *Add a passkey*, confirm, and store
the backup code WHMCS shows.

## Settings

| Setting | Meaning |
|---|---|
| Relying Party ID | The domain passkeys are bound to. Empty means the host of the WHMCS System URL (for example `billing.example.com`). Set a parent domain (`example.com`) if WHMCS might move to another subdomain later. **Changing it invalidates passkeys that are already registered**, so decide before users enrol. |
| Display Name | The name the browser shows when saving a passkey. Defaults to the company name. |
| Require User Verification | Insist on a biometric or PIN check for every sign-in, not only a touch. Off by default, because the password is already the knowledge factor. |

## Good to know

- This is a **second factor**: users still sign in with their password first.
  It does not add passwordless login.
- A user's WHMCS two-factor setup holds one method, so a user chooses
  passkeys or time based codes.
- To change their passkeys a user disables two-factor and enables it again.
  A lost device is handled with the WHMCS backup code, or by an admin
  disabling two-factor for that user.
- Passkeys are requested as non-discoverable, so they do not use up the
  limited resident-key slots on hardware keys.
- Attestation is not requested (`none`): the module does not restrict which
  authenticator models may be used.
- Rejected attempts are written to the WHMCS activity log with the reason.

## Translations

Interface text lives in `modules/security/webauthn/lang/<language>.php`,
named after the WHMCS language (`english.php`, `bulgarian.php`). Copy
`english.php`, translate the values and send a pull request. Missing keys
fall back to English.

## Tests

```sh
# verifier and module logic, with a software authenticator
php tests/run.php

# real Chromium with a virtual authenticator, against a tiny WHMCS stand-in
php -S localhost:8799 -t tests/harness &
npm i --no-save playwright-core && npx playwright-core install chromium
node tests/e2e.mjs
```

## License

MIT - see [LICENSE](LICENSE).
