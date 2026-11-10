<?php
/**
 * Dependency-free test runner: php tests/run.php
 *
 * Drives the verifier and the module entry points with a software
 * authenticator that produces real keys and signatures.
 */

require __DIR__ . '/stubs.php';
require __DIR__ . '/../modules/security/webauthn/webauthn.php';

use WhmcsPasskey\Module;
use WhmcsPasskey\WebAuthn;
use WhmcsPasskey\WebAuthnException;

$passed = 0;
$failed = 0;

function check(string $name, bool $ok): void
{
    global $passed, $failed;
    $ok ? $passed++ : $failed++;
    echo($ok ? '  ok    ' : '  FAIL  ') . $name . "\n";
}

/** Passes when $fn throws a WebAuthnException whose message contains $needle. */
function rejects(string $name, string $needle, callable $fn): void
{
    try {
        $fn();
        check($name . ' (was accepted)', false);
    } catch (WebAuthnException $e) {
        check($name, stripos($e->getMessage(), $needle) !== false);
        if (stripos($e->getMessage(), $needle) === false) {
            echo '        got: ' . $e->getMessage() . "\n";
        }
    }
}

const RP = 'billing.example.com';
const ORIGIN = 'https://billing.example.com';

// ---- verifier ---------------------------------------------------------------

echo "Verifier\n";
$wa = new WebAuthn(RP);

foreach ([-7 => 'ES256', -257 => 'RS256'] as $alg => $label) {
    $device = new SoftAuthenticator($alg);
    $c = WebAuthn::newChallenge();
    $cred = $wa->verifyRegistration($device->register(RP, $c, ORIGIN), $c);
    check("$label registration is accepted", $cred['id'] === SoftAuthenticator::b64u($device->credentialId));
    check("$label unknown transports are dropped", $cred['transports'] === ['internal']);

    $c = WebAuthn::newChallenge();
    [$index, $count] = $wa->verifyAssertion($device->assert(RP, $c, ORIGIN), $c, [$cred]);
    check("$label assertion is accepted", $index === 0 && $count === 0);
}

$device = new SoftAuthenticator();
$c = WebAuthn::newChallenge();
$cred = $wa->verifyRegistration($device->register(RP, $c, ORIGIN), $c);
$creds = [$cred];

rejects('registration with a different challenge', 'challenge', function () use ($wa, $device) {
    $wa->verifyRegistration($device->register(RP, WebAuthn::newChallenge(), ORIGIN), WebAuthn::newChallenge());
});
rejects('registration from a foreign origin', 'origin', function () use ($wa, $device, $c) {
    $wa->verifyRegistration($device->register(RP, $c, 'https://evil.example.net'), $c);
});
rejects('registration whose ID differs from authenticator data', 'credential id', function () use ($wa, $device, $c) {
    $reg = $device->register(RP, $c, ORIGIN);
    $reg['id'] = SoftAuthenticator::b64u(random_bytes(32));
    $wa->verifyRegistration($reg, $c);
});
rejects('registration without attested credential data', 'attested', function () use ($wa, $device, $c) {
    $wa->verifyRegistration($device->register(RP, $c, ORIGIN, 0x05), $c);
});
rejects('registration claiming RS256 for an EC key', 'match', function () use ($wa, $device, $c) {
    $reg = $device->register(RP, $c, ORIGIN);
    $reg['alg'] = -257;
    $wa->verifyRegistration($reg, $c);
});
rejects('registration with an unsupported algorithm', 'unsupported', function () use ($wa, $device, $c) {
    $reg = $device->register(RP, $c, ORIGIN);
    $reg['alg'] = -8;
    $wa->verifyRegistration($reg, $c);
});
rejects('registration with a garbage public key', 'unreadable', function () use ($wa, $device, $c) {
    $reg = $device->register(RP, $c, ORIGIN);
    $reg['publicKey'] = SoftAuthenticator::b64u(random_bytes(91));
    $wa->verifyRegistration($reg, $c);
});
rejects('a login assertion replayed as a registration', 'type', function () use ($wa, $device, $c) {
    $reg = $device->register(RP, $c, ORIGIN);
    $reg['clientDataJSON'] = $device->assert(RP, $c, ORIGIN)['clientDataJSON'];
    $wa->verifyRegistration($reg, $c);
});

rejects('assertion with a different challenge', 'challenge', function () use ($wa, $device, $creds) {
    $wa->verifyAssertion($device->assert(RP, WebAuthn::newChallenge(), ORIGIN), WebAuthn::newChallenge(), $creds);
});
rejects('assertion against an empty challenge', 'challenge', function () use ($wa, $device, $creds) {
    $wa->verifyAssertion($device->assert(RP, '', ORIGIN), '', $creds);
});
rejects('assertion from a phishing origin', 'origin', function () use ($wa, $device, $creds, $c) {
    $wa->verifyAssertion($device->assert(RP, $c, 'https://billing.example.com.evil.net'), $c, $creds);
});
rejects('assertion from a look-alike suffix', 'origin', function () use ($wa, $device, $creds, $c) {
    $wa->verifyAssertion($device->assert(RP, $c, 'https://evilbilling.example.com'), $c, $creds);
});
rejects('assertion over plain HTTP', 'origin', function () use ($wa, $device, $creds, $c) {
    $wa->verifyAssertion($device->assert(RP, $c, 'http://billing.example.com'), $c, $creds);
});
rejects('assertion flagged cross-origin', 'cross-origin', function () use ($wa, $device, $creds, $c) {
    $wa->verifyAssertion($device->assert(RP, $c, ORIGIN, 0x05, ['crossOrigin' => true]), $c, $creds);
});
rejects('assertion for another relying party', 'relying party', function () use ($wa, $device, $creds, $c) {
    $wa->verifyAssertion($device->assert('other.example.com', $c, ORIGIN), $c, $creds);
});
rejects('assertion without user presence', 'presence', function () use ($wa, $device, $creds, $c) {
    $wa->verifyAssertion($device->assert(RP, $c, ORIGIN, 0x00), $c, $creds);
});
rejects('assertion from an unregistered credential', 'not registered', function () use ($wa, $creds, $c) {
    $wa->verifyAssertion((new SoftAuthenticator())->assert(RP, $c, ORIGIN), $c, $creds);
});
rejects('assertion signed by a different key', 'signature', function () use ($wa, $device, $creds, $c) {
    $other = new SoftAuthenticator();
    $other->credentialId = $device->credentialId;
    $wa->verifyAssertion($other->assert(RP, $c, ORIGIN), $c, $creds);
});
rejects('assertion with tampered authenticator data', 'signature', function () use ($wa, $device, $creds, $c) {
    $resp = $device->assert(RP, $c, ORIGIN);
    $resp['authenticatorData'] = SoftAuthenticator::b64u(hash('sha256', RP, true) . chr(0x05) . pack('N', 9));
    $wa->verifyAssertion($resp, $c, $creds);
});
rejects('assertion with a truncated authenticator data', 'too short', function () use ($wa, $device, $creds, $c) {
    $resp = $device->assert(RP, $c, ORIGIN);
    $resp['authenticatorData'] = SoftAuthenticator::b64u(random_bytes(20));
    $wa->verifyAssertion($resp, $c, $creds);
});
rejects('assertion with non-base64url input', 'base64url', function () use ($wa, $device, $creds, $c) {
    $resp = $device->assert(RP, $c, ORIGIN);
    $resp['signature'] = 'not base64 !!';
    $wa->verifyAssertion($resp, $c, $creds);
});
rejects('ES256 credential re-labelled RS256 in storage', 'match', function () use ($wa, $device, $creds, $c) {
    $creds[0]['alg'] = -257;
    $wa->verifyAssertion($device->assert(RP, $c, ORIGIN), $c, $creds);
});

$strict = new WebAuthn(RP, true);
rejects('user verification required but absent', 'verification', function () use ($strict, $device, $creds, $c) {
    $strict->verifyAssertion($device->assert(RP, $c, ORIGIN, 0x01), $c, $creds);
});
[$index] = $strict->verifyAssertion($device->assert(RP, $c, ORIGIN, 0x05), $c, $creds);
check('user verification required and present', $index === 0);

$parent = new WebAuthn('example.com');
$c = WebAuthn::newChallenge();
$pcred = $parent->verifyRegistration($device->register('example.com', $c, ORIGIN), $c);
[$index] = $parent->verifyAssertion($device->assert('example.com', $c, 'https://my.example.com:8443'), $c, [$pcred]);
check('parent-domain RP ID accepts its subdomains', $index === 0);

$local = new WebAuthn('localhost');
$c = WebAuthn::newChallenge();
$lcred = $local->verifyRegistration($device->register('localhost', $c, 'http://localhost:8080'), $c);
check('http://localhost is accepted for development', $lcred['alg'] === -7);

$counting = new SoftAuthenticator(-7, true);
$c = WebAuthn::newChallenge();
$ccred = $wa->verifyRegistration($counting->register(RP, $c, ORIGIN), $c);
[, $count] = $wa->verifyAssertion($counting->assert(RP, $c, ORIGIN), $c, [$ccred]);
check('signature counter advances', $count === 2 && $ccred['count'] === 1);
$ccred['count'] = $count;
rejects('signature counter that does not advance', 'counter', function () use ($wa, $counting, $ccred, $c) {
    $counting->counter = 1;
    $wa->verifyAssertion($counting->assert(RP, $c, ORIGIN), $c, [$ccred]);
});

// ---- module entry points ----------------------------------------------------

echo "Module\n";
\WHMCS\Config\Setting::$values = ['SystemURL' => 'https://billing.example.com/whmcs/', 'CompanyName' => 'Example & Co "Hosting"'];
$_SESSION = [];
$twoFactor = new FakeTwoFactor();

function baseParams(array $extra = []): array
{
    global $twoFactor;
    return $extra + [
        'settings' => [],
        'user_info' => ['id' => 42, 'username' => 'jo@example.com', 'email' => 'jo@example.com'],
        'user_settings' => $twoFactor->settings,
        'post_vars' => [],
        'twoFactorAuthentication' => $twoFactor,
    ];
}

/** Pulls the config the browser script would receive out of the rendered HTML. */
function configOf(string $html): array
{
    preg_match('/data-config="([^"]*)"/', $html, $m);
    return json_decode(html_entity_decode($m[1] ?? '', ENT_QUOTES), true) ?: [];
}

/** Encodes a browser result the way webauthn.js does, then sanitises it the way WHMCS does. */
function posted(array $value): array
{
    $field = htmlspecialchars(SoftAuthenticator::b64u(json_encode($value)), ENT_QUOTES);
    return ['post_vars' => [Module::FIELD => $field]];
}

$config = webauthn_config();
check('config exposes the system fields', isset($config['FriendlyName']['Value'], $config['rp_id'], $config['require_uv']));

$html = webauthn_activate(baseParams());
$cfg = configOf($html);
check('activate renders a registration prompt', ($cfg['mode'] ?? '') === 'register' && strlen($cfg['challenge'] ?? '') === 43);
check('activate derives the RP ID from the System URL', ($cfg['rp']['id'] ?? '') === RP);
check('activate escapes the company name', ($cfg['rp']['name'] ?? '') === 'Example & Co "Hosting"' && strpos($html, '"Hosting"') === false);
check('activate does not expose the numeric user id', strpos($cfg['user']['id'] ?? '', '42') === false && ($cfg['user']['name'] ?? '') === 'jo@example.com');
check('activate inlines the browser script', strpos($html, 'function webauthn2faInit') !== false && substr_count($html, '</script>') === 1);

$phone = new SoftAuthenticator(-7);
$key = new SoftAuthenticator(-257, true);

$threw = '';
try {
    webauthn_activateverify(baseParams());
} catch (\WHMCS\Exception $e) {
    $threw = $e->getMessage();
}
check('activateverify without a passkey is refused', $threw !== '');

$cfg = configOf(webauthn_activate(baseParams()));
$result = webauthn_activateverify(baseParams(posted(['credentials' => [
    $phone->register(RP, $cfg['challenge'], ORIGIN),
    $key->register(RP, $cfg['challenge'], ORIGIN),
    $phone->register(RP, $cfg['challenge'], ORIGIN), // duplicate, collapses
]])));
$stored = json_decode($result['settings']['credentials'] ?? '', true);
check('activateverify stores both passkeys once', is_array($stored) && count($stored) === 2 && $result['settings']['rpid'] === RP);

$threw = '';
try {
    webauthn_activateverify(baseParams(posted(['credentials' => [$phone->register(RP, $cfg['challenge'], ORIGIN)]])));
} catch (\WHMCS\Exception $e) {
    $threw = $e->getMessage();
}
check('activateverify cannot reuse a consumed challenge', $threw !== '');

$cfg = configOf(webauthn_activate(baseParams()));
$threw = '';
try {
    webauthn_activateverify(baseParams(posted(['credentials' => [
        $phone->register(RP, $cfg['challenge'], ORIGIN),
        $key->register(RP, $cfg['challenge'], 'https://evil.example.net'),
    ]])));
} catch (\WHMCS\Exception $e) {
    $threw = $e->getMessage();
}
check('activateverify refuses the whole set if one passkey is bad', $threw !== '');

// WHMCS persists the settings (plus its own backup code) after activateverify.
$twoFactor->settings = $result['settings'] + ['backupcode' => 'hashed-backup-code'];

$cfg = configOf(webauthn_challenge(baseParams()));
check('challenge lists both passkeys', ($cfg['mode'] ?? '') === 'login' && count($cfg['allow'] ?? []) === 2 && $cfg['rpId'] === RP);
check('challenge does not leak public keys', !isset($cfg['allow'][0]['pk']) && strpos(json_encode($cfg), 'pk') === false);

check('verify accepts the phone passkey', webauthn_verify(baseParams(posted($phone->assert(RP, $cfg['challenge'], ORIGIN)))) === true);
check('verify cannot replay the same response', webauthn_verify(baseParams(posted($phone->assert(RP, $cfg['challenge'], ORIGIN)))) === false);

$cfg = configOf(webauthn_challenge(baseParams()));
check('verify accepts the hardware key', webauthn_verify(baseParams(posted($key->assert(RP, $cfg['challenge'], ORIGIN)))) === true);
$after = json_decode($twoFactor->settings['credentials'], true);
check('verify stores the advanced counter', ($after[1]['count'] ?? 0) === 2 && ($after[0]['count'] ?? -1) === 0);
check('verify keeps the other user settings', ($twoFactor->settings['backupcode'] ?? '') === 'hashed-backup-code');

$cfg = configOf(webauthn_challenge(baseParams()));
$key->counter = 1; // a clone that is behind the real key
check('verify rejects a cloned hardware key', webauthn_verify(baseParams(posted($key->assert(RP, $cfg['challenge'], ORIGIN)))) === false);

$first = configOf(webauthn_challenge(baseParams()));
webauthn_challenge(baseParams());
check('verify accepts an earlier pending challenge', webauthn_verify(baseParams(posted($phone->assert(RP, $first['challenge'], ORIGIN)))) === true);

$cfg = configOf(webauthn_challenge(baseParams()));
check('verify rejects an empty post', webauthn_verify(baseParams()) === false);
check('verify rejects after the challenge was consumed', webauthn_verify(baseParams(posted($phone->assert(RP, $cfg['challenge'], ORIGIN)))) === false);

$cfg = configOf(webauthn_challenge(baseParams()));
$_SESSION['webauthn2fa']['login'][0]['t'] = time() - 3600;
check('verify rejects an expired challenge', webauthn_verify(baseParams(posted($phone->assert(RP, $cfg['challenge'], ORIGIN)))) === false);

$cfg = configOf(webauthn_challenge(baseParams()));
check('verify rejects a stranger\'s passkey', webauthn_verify(baseParams(posted((new SoftAuthenticator())->assert(RP, $cfg['challenge'], ORIGIN)))) === false);
check('verify rejects junk', webauthn_verify(baseParams(['post_vars' => [Module::FIELD => '<script>']])) === false);

$strictParams = ['settings' => ['require_uv' => 'on']];
$cfg = configOf(webauthn_challenge(baseParams($strictParams)));
check('require_uv asks the browser for verification', ($cfg['uv'] ?? '') === 'required');
check('require_uv rejects a touch-only response', webauthn_verify(baseParams($strictParams + posted($phone->assert(RP, $cfg['challenge'], ORIGIN, 0x01)))) === false);

$override = ['settings' => ['rp_id' => 'Example.com ']];
check('rp_id setting overrides the System URL host', configOf(webauthn_activate(baseParams($override)))['rp']['id'] === 'example.com');

$none = webauthn_challenge(baseParams(['user_settings' => []]));
check('challenge without passkeys points to the backup code', strpos($none, 'backup code') !== false && strpos($none, '<script') === false);

check('rejections are written to the activity log', count($GLOBALS['activityLog']) > 0);

$english = require __DIR__ . '/../modules/security/webauthn/lang/english.php';
foreach (glob(__DIR__ . '/../modules/security/webauthn/lang/*.php') as $file) {
    $lang = require $file;
    check('language ' . basename($file, '.php') . ' has exactly the English keys', array_keys($lang) === array_keys($english));
}

echo "\n$passed passed, $failed failed\n";
exit($failed ? 1 : 0);
