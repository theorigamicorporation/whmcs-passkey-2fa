<?php
/**
 * Glue between the WHMCS two-factor module interface and WebAuthn.
 *
 * Everything travels through the forms WHMCS already renders: the browser
 * result is written to a hidden field and posted with the form, so there is
 * no extra HTTP endpoint and WHMCS's own CSRF and session handling apply.
 */

namespace WhmcsPasskey;

final class Module
{
    public const FIELD = 'webauthn_response';
    public const MAX_CREDENTIALS = 5;

    private const SESSION_KEY = 'webauthn2fa';
    private const REGISTER_TTL = 900;
    private const LOGIN_TTL = 300;
    private const MAX_PENDING = 3;

    private static int $rendered = 0;

    // ---- module entry points ------------------------------------------------

    public static function activate(array $params): string
    {
        $webauthn = self::webauthn($params);
        $user = self::userInfo($params);

        return self::render([
            'mode' => 'register',
            'challenge' => self::issueChallenge('register'),
            'rp' => ['id' => $webauthn->rpId(), 'name' => self::rpName($params)],
            'user' => [
                'id' => WebAuthn::b64uEncode(
                    hash('sha256', 'whmcs-webauthn|' . $webauthn->rpId() . '|' . $user['id'] . '|' . $user['name'], true)
                ),
                'name' => $user['name'],
            ],
            'uv' => self::requireUv($params) ? 'required' : 'preferred',
            'max' => self::MAX_CREDENTIALS,
        ]);
    }

    public static function activateVerify(array $params): array
    {
        $text = self::strings();
        $challenges = self::takeChallenges('register', self::REGISTER_TTL);
        $payload = self::payload($params);
        $submitted = is_array($payload['credentials'] ?? null) ? $payload['credentials'] : [];
        if (!$submitted) {
            self::fail($text['errNone']);
        }
        if (!$challenges) {
            self::fail($text['errExpired']);
        }

        $webauthn = self::webauthn($params);
        $credentials = [];
        foreach (array_slice($submitted, 0, self::MAX_CREDENTIALS) as $registration) {
            try {
                $credential = self::tryChallenges(
                    $challenges,
                    static function (string $challenge) use ($webauthn, $registration) {
                        return $webauthn->verifyRegistration((array) $registration, $challenge);
                    }
                );
            } catch (WebAuthnException $e) {
                self::log('registration rejected: ' . $e->getMessage());
                self::fail($text['errInvalid']);
            }
            $credentials[$credential['id']] = $credential;
        }

        return [
            'settings' => [
                'credentials' => json_encode(array_values($credentials)),
                'rpid' => $webauthn->rpId(),
            ],
        ];
    }

    public static function challenge(array $params): string
    {
        $text = self::strings();
        $credentials = self::credentials($params);
        if (!$credentials) {
            return '<div class="alert alert-danger">' . self::esc($text['noCredentials']) . '</div>';
        }

        $allow = [];
        foreach ($credentials as $credential) {
            $allow[] = [
                'id' => $credential['id'],
                'transports' => array_values((array) ($credential['transports'] ?? [])),
            ];
        }

        return self::render([
            'mode' => 'login',
            'challenge' => self::issueChallenge('login'),
            'rpId' => self::webauthn($params)->rpId(),
            'allow' => $allow,
            'uv' => self::requireUv($params) ? 'required' : 'preferred',
        ]);
    }

    public static function verify(array $params): bool
    {
        try {
            // Always consume the pending challenges, pass or fail.
            $challenges = self::takeChallenges('login', self::LOGIN_TTL);
            $payload = self::payload($params);
            $credentials = self::credentials($params);
            if (!$payload || !$challenges || !$credentials) {
                return false;
            }

            $webauthn = self::webauthn($params);
            [$index, $count] = self::tryChallenges(
                $challenges,
                static function (string $challenge) use ($webauthn, $payload, $credentials) {
                    return $webauthn->verifyAssertion($payload, $challenge, $credentials);
                }
            );

            if ($count !== (int) ($credentials[$index]['count'] ?? 0)) {
                $credentials[$index]['count'] = $count;
                self::saveCredentials($params, $credentials);
            }
            return true;
        } catch (WebAuthnException $e) {
            self::log('login rejected: ' . $e->getMessage());
        } catch (\Throwable $e) {
            self::log('login error: ' . $e->getMessage());
        }
        return false;
    }

    // ---- configuration ------------------------------------------------------

    private static function webauthn(array $params): WebAuthn
    {
        return new WebAuthn(self::rpId($params), self::requireUv($params));
    }

    private static function rpId(array $params): string
    {
        $configured = strtolower(trim((string) ($params['settings']['rp_id'] ?? '')));
        if ($configured !== '') {
            return $configured;
        }
        $host = parse_url(self::systemSetting('SystemURL'), PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            $host = preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? ''));
        }
        return strtolower((string) $host);
    }

    private static function rpName(array $params): string
    {
        $name = trim((string) ($params['settings']['rp_name'] ?? ''));
        if ($name === '') {
            $name = trim(self::systemSetting('CompanyName'));
        }
        return $name !== '' ? $name : self::rpId($params);
    }

    private static function requireUv(array $params): bool
    {
        $value = $params['settings']['require_uv'] ?? '';
        return !in_array($value, ['', '0', 0, false, null, 'off', 'no'], true);
    }

    private static function systemSetting(string $name): string
    {
        try {
            if (class_exists('\WHMCS\Config\Setting')) {
                return (string) \WHMCS\Config\Setting::getValue($name);
            }
        } catch (\Throwable $e) {
        }
        return '';
    }

    private static function userInfo(array $params): array
    {
        $info = (array) ($params['user_info'] ?? []);
        $name = trim((string) ($info['email'] ?? '')) ?: trim((string) ($info['username'] ?? ''));
        return [
            'id' => (string) ($info['id'] ?? ''),
            'name' => $name !== '' ? $name : 'user',
        ];
    }

    // ---- stored credentials -------------------------------------------------

    private static function credentials(array $params): array
    {
        $stored = $params['user_settings']['credentials'] ?? null;
        if (is_string($stored)) {
            $stored = json_decode($stored, true);
        }
        if (!is_array($stored)) {
            return [];
        }
        return array_values(array_filter($stored, static function ($credential) {
            return is_array($credential) && is_string($credential['id'] ?? null);
        }));
    }

    /**
     * Persist an advanced signature counter. Best effort: a failure here must
     * not turn a correctly verified login into a rejected one.
     */
    private static function saveCredentials(array $params, array $credentials): void
    {
        $twoFactor = $params['twoFactorAuthentication'] ?? null;
        if (!is_object($twoFactor) || !method_exists($twoFactor, 'saveUserSettings')) {
            return;
        }
        try {
            // Hand back every existing setting too, so this is correct whether
            // the core merges or replaces.
            $settings = (array) ($params['user_settings'] ?? []);
            $settings['credentials'] = json_encode(array_values($credentials));
            $twoFactor->saveUserSettings($settings);
        } catch (\Throwable $e) {
            self::log('could not store signature counter: ' . $e->getMessage());
        }
    }

    // ---- request and session ------------------------------------------------

    /**
     * The field is base64url(JSON) so it survives WHMCS's input sanitising,
     * which HTML-escapes quotes in posted values.
     */
    private static function payload(array $params): ?array
    {
        $raw = $params['post_vars'][self::FIELD] ?? ($_POST[self::FIELD] ?? '');
        if (!is_string($raw) || $raw === '' || strlen($raw) > 65536) {
            return null;
        }
        try {
            $data = json_decode(WebAuthn::b64uDecode($raw), true);
        } catch (WebAuthnException $e) {
            return null;
        }
        return is_array($data) ? $data : null;
    }

    /**
     * A few challenges may be pending at once, so rendering the form twice
     * (a second tab, a core that builds the page more than once) does not
     * invalidate the one the browser is answering.
     */
    private static function issueChallenge(string $slot): string
    {
        $challenge = WebAuthn::newChallenge();
        $pending = $_SESSION[self::SESSION_KEY][$slot] ?? [];
        $pending = is_array($pending) ? $pending : [];
        $pending[] = ['c' => $challenge, 't' => time()];
        $_SESSION[self::SESSION_KEY][$slot] = array_slice($pending, -self::MAX_PENDING);
        return $challenge;
    }

    /** Returns the unexpired pending challenges and forgets all of them. */
    private static function takeChallenges(string $slot, int $ttl): array
    {
        $pending = $_SESSION[self::SESSION_KEY][$slot] ?? [];
        unset($_SESSION[self::SESSION_KEY][$slot]);
        $valid = [];
        foreach (is_array($pending) ? $pending : [] as $entry) {
            if (is_array($entry) && is_string($entry['c'] ?? null) && time() - (int) ($entry['t'] ?? 0) <= $ttl) {
                $valid[] = $entry['c'];
            }
        }
        return $valid;
    }

    private static function tryChallenges(array $challenges, callable $verify)
    {
        $last = new WebAuthnException('No pending challenge');
        foreach ($challenges as $challenge) {
            try {
                return $verify($challenge);
            } catch (WebAuthnException $e) {
                $last = $e;
            }
        }
        throw $last;
    }

    // ---- output ---------------------------------------------------------------

    private static function render(array $config): string
    {
        $text = self::strings();
        $config['i18n'] = $text;
        $id = 'webauthn2fa-' . (++self::$rendered) . '-' . bin2hex(random_bytes(4));
        $register = $config['mode'] === 'register';
        $script = (string) file_get_contents(dirname(__DIR__) . '/webauthn.js');
        $json = json_encode($config, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return '<div id="' . $id . '" class="webauthn2fa" data-config="' . self::esc($json) . '"'
            . ' style="text-align:center;margin:0 0 16px">'
            . '<p>' . self::esc($register ? $text['registerIntro'] : $text['loginIntro']) . '</p>'
            . '<ul data-role="list" class="list-unstyled" style="margin:0 0 12px"></ul>'
            . '<p><button type="button" class="btn btn-primary" data-role="action">'
            . self::esc($register ? $text['add'] : $text['use']) . '</button></p>'
            . '<div data-role="status" role="status" aria-live="polite" style="min-height:1.5em"></div>'
            . '<input type="hidden" name="' . self::FIELD . '" value="">'
            . '</div>'
            . '<script>' . $script . "\nwebauthn2faInit(document.getElementById('" . $id . "'));</script>";
    }

    private static function esc(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function strings(): array
    {
        $dir = dirname(__DIR__) . '/lang/';
        $text = require $dir . 'english.php';
        $language = self::language();
        if ($language !== 'english' && preg_match('/^[a-z_-]+$/', $language) && is_file($dir . $language . '.php')) {
            $text = array_merge($text, require $dir . $language . '.php');
        }
        return $text;
    }

    private static function language(): string
    {
        try {
            $facade = defined('ADMINAREA') ? '\AdminLang' : '\Lang';
            if (class_exists($facade)) {
                return strtolower((string) $facade::getName());
            }
        } catch (\Throwable $e) {
        }
        return 'english';
    }

    private static function fail(string $message): void
    {
        if (class_exists('\WHMCS\Exception')) {
            throw new \WHMCS\Exception($message);
        }
        throw new \RuntimeException($message);
    }

    private static function log(string $message): void
    {
        if (function_exists('logActivity')) {
            try {
                logActivity('Passkey 2FA: ' . $message);
            } catch (\Throwable $e) {
            }
        }
    }
}
