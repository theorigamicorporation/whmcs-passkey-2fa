<?php
/**
 * Minimal WebAuthn relying-party verification for second-factor use.
 *
 * Scope is deliberately narrow: attestation "none", ES256 and RS256 keys,
 * credentials scoped to one user by an allow list. That keeps the whole
 * trust path in this one file, with no dependencies beyond ext-openssl.
 *
 * The public key is taken from the browser's getPublicKey() (a DER
 * SubjectPublicKeyInfo) instead of being decoded from the CBOR attestation
 * object. With attestation "none" neither form is signed by anything, so the
 * two are equally trustworthy, and this avoids shipping a CBOR/COSE decoder.
 */

namespace WhmcsPasskey;

final class WebAuthnException extends \RuntimeException
{
}

final class WebAuthn
{
    public const ALG_ES256 = -7;
    public const ALG_RS256 = -257;

    private const FLAG_USER_PRESENT = 0x01;
    private const FLAG_USER_VERIFIED = 0x04;
    private const FLAG_ATTESTED_DATA = 0x40;

    private const TRANSPORTS = ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card'];

    private string $rpId;
    private bool $requireUserVerification;

    public function __construct(string $rpId, bool $requireUserVerification = false)
    {
        $rpId = strtolower(trim($rpId));
        if ($rpId === '') {
            throw new WebAuthnException('Relying party ID is empty');
        }
        $this->rpId = $rpId;
        $this->requireUserVerification = $requireUserVerification;
    }

    public function rpId(): string
    {
        return $this->rpId;
    }

    public static function b64uEncode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public static function b64uDecode($text): string
    {
        if (!is_string($text) || $text === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $text)) {
            throw new WebAuthnException('Malformed base64url value');
        }
        $bin = base64_decode(strtr($text, '-_', '+/'), true);
        if ($bin === false) {
            throw new WebAuthnException('Malformed base64url value');
        }
        return $bin;
    }

    public static function newChallenge(): string
    {
        return self::b64uEncode(random_bytes(32));
    }

    /**
     * Verify the result of navigator.credentials.create().
     *
     * @param array  $reg       id, clientDataJSON, authenticatorData, publicKey
     *                          (all base64url), alg, transports
     * @param string $challenge the base64url challenge that was issued
     * @return array the credential record to store
     */
    public function verifyRegistration(array $reg, string $challenge): array
    {
        $this->checkClientData($reg['clientDataJSON'] ?? null, 'webauthn.create', $challenge);

        $auth = $this->parseAuthenticatorData(self::b64uDecode($reg['authenticatorData'] ?? null));
        if ($auth['credentialId'] === null) {
            throw new WebAuthnException('No attested credential in authenticator data');
        }
        $id = self::b64uDecode($reg['id'] ?? null);
        if (!hash_equals($auth['credentialId'], $id)) {
            throw new WebAuthnException('Credential ID does not match authenticator data');
        }

        $alg = $reg['alg'] ?? null;
        $der = self::b64uDecode($reg['publicKey'] ?? null);
        self::loadPublicKey($der, is_int($alg) ? $alg : 0);

        $transports = [];
        foreach ((array) ($reg['transports'] ?? []) as $transport) {
            if (in_array($transport, self::TRANSPORTS, true) && !in_array($transport, $transports, true)) {
                $transports[] = $transport;
            }
        }

        return [
            'id' => self::b64uEncode($id),
            'pk' => base64_encode($der),
            'alg' => $alg,
            'count' => $auth['signCount'],
            'transports' => $transports,
            'added' => time(),
        ];
    }

    /**
     * Verify the result of navigator.credentials.get().
     *
     * @param array  $resp        id, clientDataJSON, authenticatorData, signature (base64url)
     * @param string $challenge   the base64url challenge that was issued
     * @param array  $credentials stored credential records of the user logging in
     * @return array [index of the matching credential, new signature counter]
     */
    public function verifyAssertion(array $resp, string $challenge, array $credentials): array
    {
        $id = self::b64uEncode(self::b64uDecode($resp['id'] ?? null));
        $index = null;
        foreach ($credentials as $i => $credential) {
            if (is_array($credential) && is_string($credential['id'] ?? null) && hash_equals($credential['id'], $id)) {
                $index = $i;
                break;
            }
        }
        if ($index === null) {
            throw new WebAuthnException('Credential is not registered for this user');
        }
        $credential = $credentials[$index];

        $clientDataJson = $this->checkClientData($resp['clientDataJSON'] ?? null, 'webauthn.get', $challenge);
        $authData = self::b64uDecode($resp['authenticatorData'] ?? null);
        $auth = $this->parseAuthenticatorData($authData);

        $der = base64_decode((string) ($credential['pk'] ?? ''), true);
        if ($der === false || $der === '') {
            throw new WebAuthnException('Stored public key is unreadable');
        }
        $key = self::loadPublicKey($der, (int) ($credential['alg'] ?? 0));

        $signed = $authData . hash('sha256', $clientDataJson, true);
        $signature = self::b64uDecode($resp['signature'] ?? null);
        if (openssl_verify($signed, $signature, $key, OPENSSL_ALGO_SHA256) !== 1) {
            throw new WebAuthnException('Signature verification failed');
        }

        // Synced passkeys always report 0; a counter that is in use must grow.
        $stored = (int) ($credential['count'] ?? 0);
        if (($auth['signCount'] !== 0 || $stored !== 0) && $auth['signCount'] <= $stored) {
            throw new WebAuthnException('Signature counter did not increase (possible cloned authenticator)');
        }

        return [$index, $auth['signCount']];
    }

    /** @return string the raw clientDataJSON bytes */
    private function checkClientData($encoded, string $type, string $challenge): string
    {
        $json = self::b64uDecode($encoded);
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new WebAuthnException('Client data is not valid JSON');
        }
        if (($data['type'] ?? null) !== $type) {
            throw new WebAuthnException('Unexpected client data type');
        }
        $got = $data['challenge'] ?? null;
        if ($challenge === '' || !is_string($got) || !hash_equals($challenge, $got)) {
            throw new WebAuthnException('Challenge mismatch');
        }
        if (!$this->originAllowed($data['origin'] ?? null)) {
            throw new WebAuthnException('Origin not allowed');
        }
        if (!empty($data['crossOrigin'])) {
            throw new WebAuthnException('Cross-origin use is not allowed');
        }
        return $json;
    }

    /**
     * The origin must be the relying party ID or a subdomain of it, over
     * HTTPS. Plain HTTP is accepted for localhost only (development).
     */
    private function originAllowed($origin): bool
    {
        if (!is_string($origin)) {
            return false;
        }
        $parts = parse_url($origin);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($host === '') {
            return false;
        }
        $suffix = '.' . $this->rpId;
        if ($host !== $this->rpId && substr($host, -strlen($suffix)) !== $suffix) {
            return false;
        }
        if ($scheme === 'https') {
            return true;
        }
        return $scheme === 'http' && ($host === 'localhost' || substr($host, -10) === '.localhost');
    }

    private function parseAuthenticatorData(string $bin): array
    {
        if (strlen($bin) < 37) {
            throw new WebAuthnException('Authenticator data is too short');
        }
        if (!hash_equals(hash('sha256', $this->rpId, true), substr($bin, 0, 32))) {
            throw new WebAuthnException('Relying party ID hash mismatch');
        }
        $flags = ord($bin[32]);
        if (!($flags & self::FLAG_USER_PRESENT)) {
            throw new WebAuthnException('User presence flag is not set');
        }
        if ($this->requireUserVerification && !($flags & self::FLAG_USER_VERIFIED)) {
            throw new WebAuthnException('User verification is required');
        }

        $credentialId = null;
        if ($flags & self::FLAG_ATTESTED_DATA) {
            if (strlen($bin) < 55) {
                throw new WebAuthnException('Attested credential data is truncated');
            }
            $length = unpack('n', substr($bin, 53, 2))[1];
            $credentialId = substr($bin, 55, $length);
            if ($length < 1 || $length > 1023 || strlen($credentialId) !== $length) {
                throw new WebAuthnException('Credential ID length is invalid');
            }
        }

        return [
            'signCount' => unpack('N', substr($bin, 33, 4))[1],
            'credentialId' => $credentialId,
        ];
    }

    /**
     * Load a DER SubjectPublicKeyInfo and insist it is the key type the
     * algorithm claims, so a stored record cannot be verified under a
     * weaker scheme than it was registered with.
     *
     * @return \OpenSSLAsymmetricKey
     */
    private static function loadPublicKey(string $der, int $alg)
    {
        if (strlen($der) > 2048) {
            throw new WebAuthnException('Public key is too large');
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        $details = $key ? openssl_pkey_get_details($key) : false;
        // Drain OpenSSL's error queue so a parse failure cannot leak into
        // whatever the host application does with OpenSSL next.
        while (openssl_error_string() !== false) {
        }
        if (!$key || !is_array($details)) {
            throw new WebAuthnException('Public key is unreadable');
        }

        if ($alg === self::ALG_ES256) {
            $ok = $details['type'] === OPENSSL_KEYTYPE_EC
                && in_array($details['ec']['curve_name'] ?? '', ['prime256v1', 'secp256r1'], true);
        } elseif ($alg === self::ALG_RS256) {
            $ok = $details['type'] === OPENSSL_KEYTYPE_RSA && (int) $details['bits'] >= 2048;
        } else {
            throw new WebAuthnException('Unsupported public key algorithm');
        }
        if (!$ok) {
            throw new WebAuthnException('Public key does not match its algorithm');
        }
        return $key;
    }
}
