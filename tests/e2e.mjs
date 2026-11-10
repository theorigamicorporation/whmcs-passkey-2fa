/*
 * End-to-end test in real Chromium with a CDP virtual authenticator.
 *
 *   php -S localhost:8799 -t tests/harness &
 *   npm i --no-save playwright-core && node tests/e2e.mjs
 *
 * Set CHROMIUM to a browser binary if Playwright's own is not installed.
 */
import { chromium } from 'playwright-core';

const BASE = process.env.BASE_URL || 'http://localhost:8799';
let failed = 0;

function check(name, ok, detail = '') {
    if (!ok) failed++;
    console.log((ok ? '  ok    ' : '  FAIL  ') + name + (ok || !detail ? '' : '\n        ' + detail));
}

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
const context = await browser.newContext();
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));

const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');

async function addAuthenticator(options) {
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
            ...options,
        },
    });
    return authenticatorId;
}

const result = () => page.locator('#result').innerText();
const status = () => page.locator('[data-role=status]').innerText();
const stored = async () => JSON.parse(await page.locator('#stored').innerText());

await page.goto(BASE + '/?p=reset');

// ---- setup ------------------------------------------------------------------

const platform = await addAuthenticator({ transport: 'internal', hasResidentKey: true });

await page.goto(BASE + '/?p=setup');
check('finish button is hidden until a passkey is added', !(await page.locator('[data-role=finish]').isVisible()));
await page.evaluate(() => document.querySelector('form').requestSubmit());
await page.waitForFunction(() => document.querySelector('#result').textContent !== '');
check('setup without a passkey is refused', (await result()).startsWith('SETUP FAILED'), await result());

await page.click('[data-role=action]');
await page.waitForSelector('[data-role=list] li');
check('first passkey is listed', (await page.locator('[data-role=list] li').count()) === 1, await status());

// Same authenticator again: the browser must refuse it via excludeCredentials.
await page.click('[data-role=action]');
await page.waitForFunction(() => document.querySelector('[data-role=status]').className.includes('danger'));
check('the same authenticator cannot be added twice', (await page.locator('[data-role=list] li').count()) === 1, await status());

// A second device: a USB security key that keeps a signature counter.
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: platform });
const usb = await addAuthenticator({ transport: 'usb', hasResidentKey: false });
await page.click('[data-role=action]');
await page.waitForFunction(() => document.querySelectorAll('[data-role=list] li').length === 2);
check('second passkey is listed', true);

await page.click('[data-role=finish]');
check('setup stores two passkeys', (await result()) === 'SETUP OK 2', await result());
const afterSetup = JSON.parse((await stored()).credentials);
check('stored records carry key, algorithm and transports',
    afterSetup.length === 2 && afterSetup.every((c) => c.pk && c.alg === -7 && c.transports.length > 0),
    JSON.stringify(afterSetup));

// ---- login ------------------------------------------------------------------

// The USB key is plugged in: the prompt starts by itself and the form posts.
await page.goto(BASE + '/?p=login');
await page.waitForFunction(() => document.querySelector('#result').textContent.startsWith('LOGIN'));
check('login starts automatically and succeeds', (await result()) === 'LOGIN OK', await result());
const afterLogin = JSON.parse((await stored()).credentials);
check('signature counter was stored', afterLogin[1].count > afterSetup[1].count,
    `${afterSetup[1].count} -> ${afterLogin[1].count}`);
check('other user settings survive the save', (await stored()).backupcode === 'kept');

// No authenticator present: nothing is posted until the user acts.
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: usb });
await page.goto(BASE + '/?p=login');
await page.waitForTimeout(800);
check('login does not post without a passkey', (await result()) === '', await result());

// Posting the form without a passkey response must not log in.
await page.evaluate(() => HTMLFormElement.prototype.submit.call(document.querySelector('form')));
await page.waitForFunction(() => document.querySelector('#result').textContent.startsWith('LOGIN'));
check('an empty form post is rejected', (await result()) === 'LOGIN FAILED', await result());

// A different key with none of this user's credentials cannot log in.
const stranger = await addAuthenticator({ transport: 'usb', hasResidentKey: false });
await page.goto(BASE + '/?p=login');
await page.waitForTimeout(1200);
check('a key that is not registered gets nowhere', (await result()) === '', await result());
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: stranger });

// Enrol again with a fresh key: the new set replaces the old one.
const restored = await addAuthenticator({ transport: 'usb', hasResidentKey: false });
await page.goto(BASE + '/?p=setup');
await page.click('[data-role=action]');
await page.waitForSelector('[data-role=list] li');
await page.click('[data-role=finish]');
check('re-enrolling replaces the stored passkeys', (await result()) === 'SETUP OK 1', await result());

// The theme's own "Login" button must start the passkey prompt, not post an
// empty response. Suppress the automatic start so the button is what runs it.
await page.addInitScript(() => {
    const original = window.setTimeout;
    window.setTimeout = (fn, ms, ...rest) => (ms === 300 ? 0 : original(fn, ms, ...rest));
});
await page.goto(BASE + '/?p=login');
await page.waitForTimeout(600);
check('nothing happens until the user acts when autostart is unavailable', (await result()) === '', await result());
await page.click('#btnLogin1');
await page.waitForFunction(() => document.querySelector('#result').textContent.startsWith('LOGIN'));
check('the theme Login button runs the passkey and logs in', (await result()) === 'LOGIN OK', await result());

// User verification required by the admin, on a key that cannot verify.
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: restored });
const noUv = await addAuthenticator({ transport: 'usb', hasResidentKey: false, hasUserVerification: false, isUserVerified: false });
await page.goto(BASE + '/?p=setup');
await page.click('[data-role=action]');
await page.waitForSelector('[data-role=list] li');
await page.click('[data-role=finish]');
await page.goto(BASE + '/?p=login&uv=on');
await page.click('[data-role=action]');
await page.waitForTimeout(1200);
check('a key without user verification cannot pass when it is required', (await result()) !== 'LOGIN OK', await result());
await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: noUv });

check('no script errors on any page', errors.length === 0, errors.join(' | '));

await browser.close();
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
