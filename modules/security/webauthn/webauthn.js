/*
 * Browser side of the WHMCS passkey two-factor module. Inlined by the module
 * next to the markup it drives; the WebAuthn result goes into a hidden field
 * and travels with the form WHMCS already renders.
 */
function webauthn2faInit(root) {
    'use strict';
    if (!root || root.getAttribute('data-ready')) {
        return;
    }
    root.setAttribute('data-ready', '1');

    var cfg = JSON.parse(root.getAttribute('data-config'));
    var t = cfg.i18n;
    var input = root.querySelector('input[type=hidden]');
    var statusEl = root.querySelector('[data-role=status]');
    var listEl = root.querySelector('[data-role=list]');
    var button = root.querySelector('[data-role=action]');

    // The module output normally sits inside the form WHMCS submits. If a
    // theme renders it elsewhere in the setup modal, move the field into it.
    var form = root.closest('form') || document.querySelector('#modalAjax form');
    if (form && !form.contains(input)) {
        form.appendChild(input);
    }

    function setStatus(message, kind) {
        statusEl.textContent = message || '';
        statusEl.className = kind ? 'text-' + kind : '';
    }

    function encode(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function decode(text) {
        var binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // base64url(JSON): survives the HTML escaping WHMCS applies to input.
    function pack(value) {
        return encode(new TextEncoder().encode(JSON.stringify(value)));
    }

    function describe(error) {
        if (error && error.name === 'NotAllowedError') {
            return t.cancelled;
        }
        if (error && error.name === 'InvalidStateError') {
            return t.duplicate;
        }
        if (error && error.name === 'SecurityError') {
            return t.domain;
        }
        return t.failed + (error && error.message ? ' (' + error.message + ')' : '');
    }

    if (!window.PublicKeyCredential || !navigator.credentials || !window.isSecureContext) {
        button.disabled = true;
        setStatus(t.unsupported, 'danger');
        return;
    }

    if (cfg.mode === 'register') {
        var registered = [];

        button.addEventListener('click', function () {
            button.disabled = true;
            setStatus(t.waiting);
            navigator.credentials.create({
                publicKey: {
                    challenge: decode(cfg.challenge),
                    rp: cfg.rp,
                    user: { id: decode(cfg.user.id), name: cfg.user.name, displayName: cfg.user.name },
                    pubKeyCredParams: [
                        { type: 'public-key', alg: -7 },
                        { type: 'public-key', alg: -257 }
                    ],
                    // A second factor is looked up by its ID, so it does not
                    // need to occupy a discoverable slot on a hardware key.
                    authenticatorSelection: {
                        residentKey: 'discouraged',
                        requireResidentKey: false,
                        userVerification: cfg.uv
                    },
                    attestation: 'none',
                    timeout: 120000,
                    excludeCredentials: registered.map(function (c) {
                        return { type: 'public-key', id: decode(c.id) };
                    })
                }
            }).then(function (credential) {
                var response = credential.response;
                var publicKey = typeof response.getPublicKey === 'function' ? response.getPublicKey() : null;
                if (!publicKey || typeof response.getAuthenticatorData !== 'function') {
                    throw new Error(t.unsupported);
                }
                registered.push({
                    id: encode(credential.rawId),
                    clientDataJSON: encode(response.clientDataJSON),
                    authenticatorData: encode(response.getAuthenticatorData()),
                    publicKey: encode(publicKey),
                    alg: response.getPublicKeyAlgorithm(),
                    transports: typeof response.getTransports === 'function' ? response.getTransports() : []
                });
                input.value = pack({ credentials: registered });

                var item = document.createElement('li');
                item.className = 'text-success';
                item.textContent = '✓ ' + t.item.replace('%d', String(registered.length));
                listEl.appendChild(item);
                button.textContent = t.addAnother;
                setStatus(t.added, 'success');
            }).catch(function (error) {
                setStatus(describe(error), 'danger');
            }).then(function () {
                button.disabled = registered.length >= cfg.max;
            });
        });
        return;
    }

    var running = false;
    var done = false;

    function signIn(automatic) {
        if (running || done) {
            return;
        }
        running = true;
        setStatus(t.waiting);
        navigator.credentials.get({
            publicKey: {
                challenge: decode(cfg.challenge),
                rpId: cfg.rpId,
                allowCredentials: cfg.allow.map(function (c) {
                    var descriptor = { type: 'public-key', id: decode(c.id) };
                    if (c.transports && c.transports.length) {
                        descriptor.transports = c.transports;
                    }
                    return descriptor;
                }),
                userVerification: cfg.uv,
                timeout: 120000
            }
        }).then(function (assertion) {
            input.value = pack({
                id: encode(assertion.rawId),
                clientDataJSON: encode(assertion.response.clientDataJSON),
                authenticatorData: encode(assertion.response.authenticatorData),
                signature: encode(assertion.response.signature)
            });
            done = true;
            button.disabled = true;
            setStatus(t.verifying, 'success');
            if (form) {
                // Not form.submit(): a control named "submit" would shadow it.
                HTMLFormElement.prototype.submit.call(form);
            }
        }).catch(function (error) {
            // Some browsers refuse a prompt that no click asked for; that is
            // not an error worth showing, the button is right there.
            setStatus(automatic ? '' : describe(error), automatic ? '' : 'danger');
        }).then(function () {
            running = false;
        });
    }

    button.addEventListener('click', function () {
        signIn(false);
    });

    // Themes add their own "Login" submit button to this form. Without a
    // passkey response it would post an empty field, so make it start the
    // passkey prompt instead.
    if (form) {
        form.addEventListener('submit', function (event) {
            if (!done) {
                event.preventDefault();
                event.stopImmediatePropagation();
                signIn(false);
            }
        }, true);
    }

    setTimeout(function () {
        signIn(true);
    }, 300);
}
