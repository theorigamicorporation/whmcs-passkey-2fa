<?php
/**
 * A stand-in for the two WHMCS screens that host a 2FA module, for driving
 * the real browser script end to end:
 *
 *   php -S localhost:8799 -t tests/harness
 *
 *   /?p=setup   the "enable two-factor" step (module output inside a form)
 *   /?p=login   the login challenge, laid out like the Lagom theme: the
 *               module output followed by the theme's own submit button
 *
 * It mimics the WHMCS behaviours the module has to live with: posted values
 * are HTML-escaped, and user settings are merged on save.
 */

session_start();

require __DIR__ . '/../stubs.php';
require __DIR__ . '/../../modules/security/webauthn/webauthn.php';

\WHMCS\Config\Setting::$values = ['SystemURL' => 'http://localhost:8799/', 'CompanyName' => 'Harness Hosting'];

$store = sys_get_temp_dir() . '/webauthn-harness-user.json';
$twoFactor = new FakeTwoFactor();
$twoFactor->settings = is_file($store) ? (json_decode(file_get_contents($store), true) ?: []) : [];

$post = array_map(static function ($value) {
    return is_string($value) ? htmlspecialchars($value, ENT_QUOTES) : $value;
}, $_POST);

$params = [
    'settings' => ['require_uv' => $_GET['uv'] ?? ''],
    'user_info' => ['id' => 7, 'username' => 'harness@example.com', 'email' => 'harness@example.com'],
    'user_settings' => $twoFactor->settings,
    'post_vars' => $post,
    'twoFactorAuthentication' => $twoFactor,
];

$page = $_GET['p'] ?? 'setup';
$message = '';
$body = '';

if ($page === 'reset') {
    @unlink($store);
    $_SESSION = [];
    $message = 'RESET';
} elseif ($page === 'setup') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        try {
            $result = webauthn_activateverify($params);
            $twoFactor->saveUserSettings($result['settings'] + ['backupcode' => 'kept']);
            $message = 'SETUP OK ' . count(json_decode($result['settings']['credentials'], true));
        } catch (\Throwable $e) {
            $message = 'SETUP FAILED: ' . $e->getMessage();
        }
    }
    $body = '<form method="post" id="frmSetup"><input type="hidden" name="2fasetup" value="1">'
        . webauthn_activate($params)
        . '<button type="submit" id="btnSubmit" class="btn">Submit</button></form>';
} elseif ($page === 'login') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $message = webauthn_verify($params) ? 'LOGIN OK' : 'LOGIN FAILED';
    }
    // "submit" as a control name on purpose: it shadows form.submit().
    $body = '<form method="post" id="frmTwoFactorChallenge">'
        . webauthn_challenge($params)
        . '<button type="submit" id="btnLogin1" name="submit" class="btn">Login</button></form>';
}

file_put_contents($store, json_encode($twoFactor->settings));
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>WHMCS passkey 2FA harness</title></head>
<body>
<div id="result"><?= htmlspecialchars($message) ?></div>
<pre id="stored"><?= htmlspecialchars(json_encode($twoFactor->settings)) ?></pre>
<?= $body ?>
</body>
</html>
