<?php
/**
 * Passkey / Security Key two-factor authentication for WHMCS (WebAuthn).
 *
 * @license MIT
 * @link    https://github.com/theorigamicorporation/whmcs-passkey-2fa
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/WebAuthn.php';
require_once __DIR__ . '/lib/Module.php';

use WhmcsPasskey\Module;

function webauthn_config()
{
    return [
        'FriendlyName' => [
            'Type' => 'System',
            'Value' => 'Passkey / Security Key',
        ],
        'ShortDescription' => [
            'Type' => 'System',
            'Value' => 'Sign in with a fingerprint, face, device PIN or a hardware security key.',
        ],
        'Description' => [
            'Type' => 'System',
            'Value' => 'Uses WebAuthn (FIDO2) as the second factor: Touch ID, Face ID, Windows Hello, '
                . 'Android, password-manager passkeys and hardware keys such as YubiKey. Phishing '
                . 'resistant, with nothing to type. Open source, verified entirely on your server.',
        ],
        'rp_id' => [
            'FriendlyName' => 'Relying Party ID',
            'Type' => 'text',
            'Size' => '30',
            'Description' => 'Leave empty to use the host name of the WHMCS System URL. Set a parent '
                . 'domain (example.com) to keep passkeys valid if WHMCS moves to another subdomain. '
                . 'Changing this invalidates passkeys that are already registered.',
        ],
        'rp_name' => [
            'FriendlyName' => 'Display Name',
            'Type' => 'text',
            'Size' => '30',
            'Description' => 'Name shown by the browser when saving a passkey. Defaults to the company name.',
        ],
        'require_uv' => [
            'FriendlyName' => 'Require User Verification',
            'Type' => 'yesno',
            'Description' => 'Insist on a biometric or PIN check for every sign-in, not just a touch.',
        ],
    ];
}

function webauthn_activate($params)
{
    return Module::activate((array) $params);
}

function webauthn_activateverify($params)
{
    return Module::activateVerify((array) $params);
}

function webauthn_challenge($params)
{
    return Module::challenge((array) $params);
}

function webauthn_verify($params)
{
    return Module::verify((array) $params);
}
