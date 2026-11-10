<?php
/**
 * Just enough of WHMCS to load the module outside WHMCS.
 */

namespace WHMCS\Config {
    class Setting
    {
        public static array $values = [];

        public static function getValue($name)
        {
            return self::$values[$name] ?? '';
        }
    }
}

namespace WHMCS {
    class Exception extends \Exception
    {
    }
}

namespace {
    if (!defined('WHMCS')) {
        define('WHMCS', true);
    }

    $GLOBALS['activityLog'] = [];

    function logActivity($message)
    {
        $GLOBALS['activityLog'][] = $message;
    }

    /** Stands in for WHMCS\TwoFactorAuthentication: merges, like the core. */
    class FakeTwoFactor
    {
        public array $settings = [];

        public function saveUserSettings($settings)
        {
            $this->settings = array_merge($this->settings, $settings);
        }
    }

    /** A software authenticator: makes real keys and real signatures. */
    class SoftAuthenticator
    {
        public string $credentialId;
        public int $counter = 0;
        public int $alg;
        private $key;

        public function __construct(int $alg = -7, bool $counting = false)
        {
            $this->alg = $alg;
            $this->key = $alg === -7
                ? openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'])
                : openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            $this->credentialId = random_bytes(32);
            $this->counter = $counting ? 1 : 0;
        }

        public static function b64u(string $bin): string
        {
            return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
        }

        public function publicKeyDer(): string
        {
            $pem = openssl_pkey_get_details($this->key)['key'];
            return base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem));
        }

        private function clientData(string $type, string $challenge, string $origin, array $extra = []): string
        {
            return json_encode(
                $extra + ['type' => $type, 'challenge' => $challenge, 'origin' => $origin, 'crossOrigin' => false],
                JSON_UNESCAPED_SLASHES
            );
        }

        public function register(string $rpId, string $challenge, string $origin, int $flags = 0x45): array
        {
            $authData = hash('sha256', $rpId, true) . chr($flags) . pack('N', $this->counter)
                . str_repeat("\0", 16) . pack('n', strlen($this->credentialId)) . $this->credentialId
                . "\xa5\x01\x02\x03\x26"; // stand-in for the COSE key, which the module does not read

            return [
                'id' => self::b64u($this->credentialId),
                'clientDataJSON' => self::b64u($this->clientData('webauthn.create', $challenge, $origin)),
                'authenticatorData' => self::b64u($authData),
                'publicKey' => self::b64u($this->publicKeyDer()),
                'alg' => $this->alg,
                'transports' => ['internal', 'bogus'],
            ];
        }

        public function assert(string $rpId, string $challenge, string $origin, int $flags = 0x05, array $extra = []): array
        {
            if ($this->counter > 0) {
                $this->counter++;
            }
            $clientData = $this->clientData('webauthn.get', $challenge, $origin, $extra);
            $authData = hash('sha256', $rpId, true) . chr($flags) . pack('N', $this->counter);
            openssl_sign($authData . hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);

            return [
                'id' => self::b64u($this->credentialId),
                'clientDataJSON' => self::b64u($clientData),
                'authenticatorData' => self::b64u($authData),
                'signature' => self::b64u($signature),
            ];
        }
    }
}
