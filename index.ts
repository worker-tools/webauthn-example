// deno-lint-ignore-file no-explicit-any no-unused-vars require-await ban-unused-ignore
import { WorkerRouter } from '@worker-tools/router'
import { combine, plainCookies, storageSession, accepts, bodyParser, contentTypes, flushed, FORM, FORM_DATA } from '@worker-tools/middleware';
import { html, HTMLResponse } from '@worker-tools/html'
import { StorageArea } from '@worker-tools/kv-storage';
import { ok, unauthorized, badRequest, conflict, seeOther } from '@worker-tools/response-creators';
import { JSONResponse } from '@worker-tools/json-fetch'
import * as Structured from '@worker-tools/structured-json';
import { WebUUID } from 'web-uuid';
import { compareBufferSources } from 'typed-array-utils';

import { Fido2Lib } from "fido2-lib/dist/main.js";

type User = {
  id: BufferSource,
  name: string,
  displayName: string,
  authenticators: { [x: string]: any }[],
}

type Session = {
  loggedIn: boolean, 
  userHandle?: string, 
  userId?: BufferSource, 
  challenge?: ArrayBuffer,
}

const isCFWorkers = navigator.userAgent?.includes('Cloudflare-Workers')

// FIXME: Need to provide correct location here when running Deno without `--location`.
const location = self.location ?? new URL('http://localhost:8787');

const users = new StorageArea('user')

const fido2 = new Fido2Lib({
  authenticatorUserVerification: 'preferred' // setting a fixed value prevents warning in chrome
})

const sessionMW = combine(
  plainCookies(),
  isCFWorkers ? x => x : flushed(), // doesn't work in cf workers rn
  storageSession<Session>({ 
    defaultSession: { loggedIn: false }, 
    storage: new StorageArea('session'),
  }),
)

const formMW = combine(
  accepts([FORM, FORM_DATA]),
  bodyParser(),
)

const jsonMW = combine(
  accepts(['application/json']),
  bodyParser(),
)

export const router = new WorkerRouter()

const style = html`
  <style>
    :root { 
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans", "Helvetica Neue", Arial, sans-serif;
      color-scheme: dark light;
      background: var(--background);
      color: var(--color);
      --background: #fff;
      --color: #000;
    }
    pre, code {
      font-family: ui-monospace, Menlo, Monaco, "Cascadia Mono", "Segoe UI Mono", "Roboto Mono", "Oxygen Mono", "Ubuntu Monospace", "Source Code Pro", "Fira Mono", "Droid Sans Mono", "Courier New", monospace;
      font-size: .85em;
    }
    @media (prefers-color-scheme:dark) {
      :root {
        --background: #000;
        --color: #fff;
      }
    }
  </style>
`
router.get('/', sessionMW, async (req, { session }) => {
  return new HTMLResponse(html`<!doctype html><html lang="en">
<body>
  ${style}
  <h1>Workers WebAuthn Example</h1>
  <p>Password-less login for <a href="https://workers.js.org">Worker Runtimes</a>.
     Find the <a href="https://github.com/worker-tools/webauthn-example">Source</a> on Github.</p> 
  <form method="POST">
    ${session.loggedIn 
      ? html`<div>
        <p>Hello, <strong>${session.userHandle}</strong>.</p>
        <button type="submit" formaction="/logout">Logout</button>
        ${(async () => {
          const user = Structured.toJSON(await users.get<User>(session.userHandle!))
          delete user.$types
          return html`<pre>${JSON.stringify(user, null, 2)}</pre>`;
        })()}
      </div>`
      : html`<div>
        <input type="text" name="user-handle" placeholder="Username" />
        <button type="submit" formaction="/register">Register</button>
        <button type="submit" formaction="/login">Login</button>
        <button type="submit" formaction="/response" hidden>Scan key…</button>
        <span class="hint"></span>
      </div>`}
  </form>
  <script type="module">
    import { JSONRequest } from 'https://cdn.skypack.dev/@worker-tools/json-fetch'
    import * as Structured from 'https://cdn.skypack.dev/@worker-tools/structured-json'

    const timeout = n => new Promise(r => setTimeout(r, n))
    const isSafari = ua => !!ua && ua.includes('Safari/') && !(ua.includes('Chrome/') || ua.includes('Chromium/'))

    const form = document.querySelector('form');
    const input = form.querySelector('input[name=user-handle]')
    const registerButton = form.querySelector('button[formaction$=register]')
    const loginButton = form.querySelector('button[formaction$=login]')
    const responseButton = form.querySelector('button[formaction$=response]')
    const hint = form.querySelector('.hint')

    function showResponse() {
      input.disabled = true;
      registerButton.hidden = true;
      loginButton.hidden = true;
      responseButton.hidden = false;
      // Safari has a requirement that doesn't allow triggering the webauthn dialog outside a user-interaction,
      // so we just focus the button instead:
      if (isSafari(navigator.userAgent)) 
        requestAnimationFrame(() => responseButton.focus());
      else 
        requestAnimationFrame(() => responseButton.click());
    }

    async function register() {
      hint.textContent = ''
      const orig = registerButton.textContent;
      registerButton.textContent = 'Loading…';
      const res = await fetch('/register', { method: 'POST', body: new FormData(form) });
      if (res.ok) {
        const publicKey = Structured.fromJSON(await res.json());
        showResponse();
        return publicKey
      } else {
        registerButton.textContent = orig;
        hint.textContent = res.statusText
      }
    }

    async function login() {
      hint.textContent = '';
      const orig = loginButton.textContent;
      loginButton.textContent = 'Loading…';
      const res = await fetch('/login', { method: 'POST', body: new FormData(form) });
      if (res.ok) {
        const publicKey = Structured.fromJSON(await res.json());
        showResponse();
        return publicKey;
      } else  {
        loginButton.textContent = orig;
        hint.textContent = res.statusText;
      }
    }

    async function handleResponse(publicKey) {
      if (publicKey) {
        const cred = 'attestation' in publicKey
          ? await navigator.credentials.create({ publicKey })
          : await navigator.credentials.get({ publicKey });
        responseButton.disabled = true;
        const body = Structured.toJSON(credToJSON(cred));
        const res = await fetch(new JSONRequest('/response', { method: 'POST', body }));
        if (res.ok) { 
          await timeout(250);
          location.reload();
        }
      }
    }

    async function logout() {
      const res = await fetch('/logout', { method: 'POST' });
      if (res.ok) { 
        await timeout(250);
        location.reload();
      }
    }

    // Sadly, this is necessary to serialize WebAuthn credentials...
    function credToJSON(x) {
      if (x instanceof ArrayBuffer) return x;
      if (Array.isArray(x)) { const arr = []; for (const i of x) arr.push(credToJSON(i)); return arr }
      if (x != null && typeof x === 'object') { const obj = {}; for (const key in x) if (typeof x[key] !== 'function') obj[key] = credToJSON(x[key]); return obj }
      return x;
    }

    let publicKey;
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const { formAction } = ev.submitter;
      if (formAction.endsWith('/register')) {
        publicKey = await register();
      }
      if (formAction.endsWith('/login')) {
        publicKey = await login();
      }
      if (formAction.endsWith('/response')) {
        await handleResponse(publicKey);
      }
      if (formAction.endsWith('/logout')) {
        await logout();
      }
    })
  </script>
</body>

</html>`)
})

router.post('/register', combine(sessionMW, formMW), async (req, { session, body }) => {
  const userHandle = body.get('user-handle') as string;
  if (!userHandle) throw badRequest()
  if (await users.get<User>(userHandle)) { throw conflict() }

  const options = await fido2.attestationOptions() as any;
  options.user = {
    id: new WebUUID(),
    name: userHandle,
    displayName: userHandle,
  };

  session.userId = options.user.id
  session.userHandle = userHandle
  session.challenge = options.challenge

  return new JSONResponse(Structured.toJSON(options))
})

const getAllowCredentials = (user: User) => user.authenticators.map(authr => ({
  type: 'public-key',
  id: authr.credId,
  transports: authr.transports,
})) as any

router.post('/login', combine(sessionMW, formMW), async (req, { session, body }) => {
  const userHandle = body.get('user-handle') as string;
  if (!userHandle) throw badRequest()

  const user = await users.get<User>(userHandle)
  if (!user) { throw unauthorized() }

  const options = await fido2.assertionOptions() as any;
  options.allowCredentials = getAllowCredentials(user),

  session.userHandle = userHandle
  session.challenge = options.challenge

  return new JSONResponse(Structured.toJSON(options))
})


router.post('/response', combine(sessionMW, jsonMW), async (req, { session, body }) => {
  const data = Structured.fromJSON(body)

  if (!session.userHandle) throw unauthorized();

  if (data.response.attestationObject != null) {
    // register
    const reg = await fido2.attestationResult(data, {
      challenge: session.challenge,
      origin: location.origin,
      factor: "either"
    })
    if (!reg.authnrData) throw unauthorized();
    console.log(reg)

    const user = {
      id: session.userId,
      name: session.userHandle,
      displayName: session.userHandle,
      authenticators: [Object.fromEntries(reg.authnrData)],
    }

    await users.set(user.name, user, { 
      expirationTtl: 60 * 60, // FIXME: Demo only, remove for real app
    }) 
    session.loggedIn = true
    delete session.userId
    delete session.challenge;

    return ok()
  } 
  else if (data.response.authenticatorData != null) {
    // login
    const user = await users.get<User>(session.userHandle)
    if (!user) throw unauthorized()

    const auth = user.authenticators.find(x => compareBufferSources(x.credId, data.rawId))
    if (!auth) throw unauthorized();

    // Some devices don't provide a user handle, but required by fido-lib, so we just patch it...
    data.response.userHandle ||= 'buffer' in user.id ? user.id.buffer : user.id

    const reg = await fido2.assertionResult(data, {
      allowCredentials: getAllowCredentials(user),
      challenge: session.challenge,
      origin: location.origin,
      factor: "either",
      publicKey: auth.credentialPublicKeyPem,
      prevCounter: auth.counter,
      userHandle: user.id,
    })
    if (!reg.authnrData) throw unauthorized();
    console.log(reg)

    auth.counter = reg.authnrData.get('counter');

    await users.set(session.userHandle, user)
    session.loggedIn = true
    delete session.challenge;

    return ok()
  }

  return badRequest()
})

router.post('/logout', sessionMW, (req, { session, handled }) => {
  session.loggedIn = false;
  delete session.userHandle;
  const res = seeOther('/')
  return res;
})

router.recover(
  '*', 
  contentTypes(['text/html', 'application/json', '*/*']), 
  (req, { type, response: { status, statusText }, error }) => {
    const message = error instanceof Error ? error.message : ''
    if (error) console.warn(error)
    if (type === 'application/json') { 
      return new JSONResponse({ 
        error: { status, statusText, message } 
      }, { status, statusText }) // FIXME
    }
    return new HTMLResponse(html`<html>
      <body>
        ${style}
        Something went wrong: ${status} ${statusText} ${message}
      </body>
    </html>`, { status, statusText }) // FIXME
  },
)

router.addEventListener('error', ev => console.warn(ev.message));

router.get('/favicon.ico', () => ok());
