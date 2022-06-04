// deno-lint-ignore-file no-explicit-any no-unused-vars require-await ban-unused-ignore
import { WorkerRouter } from '@worker-tools/router'
import { combine, plainCookies, storageSession, accepts, bodyParser, contentTypes, flushed, FORM, FORM_DATA } from '@worker-tools/middleware';
import { html, HTMLResponse } from '@worker-tools/html'
import { StorageArea } from '@worker-tools/kv-storage';
import { ok, unauthorized, badRequest, conflict } from '@worker-tools/response-creators';
import { JSONResponse } from '@worker-tools/json-fetch'
import * as Structured from '@worker-tools/structured-json';
import { WebUUID } from 'web-uuid';
import { compareBufferSources } from 'typed-array-utils';

import { Fido2Lib } from "fido2-lib/dist/main.js";

// FIXME
const location = globalThis.location || new URL('http://localhost:8888');

const users = new StorageArea('user')

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

const f2l = new Fido2Lib({
  authenticatorUserVerification: 'preferred' 
})

const sessionMW = combine(
  plainCookies(),
  flushed(),
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
      color-scheme: dark light;
      background: var(--background);
      color: var(--color);
      --background: #fff;
      --color: #000;
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
  return new HTMLResponse(html`<html>
<body>
  ${style}
  <form method="POST">
  ${session.loggedIn 
    ? html`<div>
      <p>Hello, ${session.userHandle}.</p><button type="submit" formaction="/logout">Logout</button>
      ${async () => {
        const user = Structured.toJSON(await users.get<User>(session.userHandle!))
        delete user.$types
        return html`<pre>${JSON.stringify(user, null, 2)}</pre>`;
      }}
    </div>`
    : html`<div>
      <input type="text" name="user-handle" placeholder="Username" />
      <button type="submit" formaction="/register">Register</button>
      <button type="submit" formaction="/login">Login</button>
      <button type="submit" formaction="/response" style="display:none">Scan key...</button>
      <span></span>
    </div>`}
  </form>
  <script type="module">
    import { JSONRequest } from 'https://cdn.skypack.dev/@worker-tools/json-fetch'
    import * as Structured from 'https://cdn.skypack.dev/@worker-tools/structured-json'

    const form = document.querySelector('form');
    const input = form.querySelector('input[name=user-handle]')
    const registerButton = form.querySelector('button[formaction$=register]')
    const loginButton = form.querySelector('button[formaction$=login]')
    const responseButton = form.querySelector('button[formaction$=response]')
    const hint = form.querySelector('span')

    let publicKey;
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (ev.submitter.formAction.endsWith('/register')) {
        hint.textContent = ''
        const orig = registerButton.textContent;
        registerButton.textContent = 'Loading...'

        const res = await fetch('/register', { method: 'POST', body: new FormData(form) });
        if (res.ok) {
          publicKey = Structured.fromJSON(await res.json());
          registerButton.style.display = 'none';
          loginButton.style.display = 'none';
          responseButton.style.display = 'inline';
          input.disabled = true;
        } else {
          registerButton.textContent = orig;
          hint.textContent = res.statusText
        }
      }
      else if (ev.submitter.formAction.endsWith('/login')) {
        hint.textContent = ''
        const orig = loginButton.textContent;
        loginButton.textContent = 'Loading...'

        const res = await fetch('/login', { method: 'POST', body: new FormData(form) });
        if (res.ok) {
          publicKey = Structured.fromJSON(await res.json());
          registerButton.style.display = 'none';
          loginButton.style.display = 'none';
          responseButton.style.display = 'inline';
          input.disabled = true;
        } else  {
          loginButton.textContent = orig;
          hint.textContent = res.statusText
        }
      }
      else if (ev.submitter.formAction.endsWith('/response')) {
        if (publicKey) {
          const cred = 'attestation' in publicKey
            ? await navigator.credentials.create({ publicKey })
            : await navigator.credentials.get({ publicKey });
          const body = Structured.toJSON(credToJSON(cred));
          const res2 = await fetch(new JSONRequest('/response', { method: 'POST', body }));
          if (res2.ok) { await res2.text(); location.reload() }
        }
      }
      else if (ev.submitter.formAction.endsWith('/logout')) {
        const res = await fetch('/logout', { method: 'POST' });
        if (res.ok) { await res.text(); location.reload() }
      }
    })

    // Sadly, this is necessary to stringify WebAuthn credentials...
    function credToJSON(x) {
      if (x instanceof ArrayBuffer) return x;
      if (Array.isArray(x)) { const arr = []; for (const i of x) arr.push(credToJSON(i)); return arr }
      if (x != null && typeof x === 'object') { const obj = {}; for (const key in x) if (typeof x[key] !== 'function') obj[key] = credToJSON(x[key]); return obj }
      return x;
    }
  </script>
</body>

</html>`)
})

router.post('/register', combine(sessionMW, formMW), async (req, { session, body }) => {
  const userHandle = body.get('user-handle') as string;
  if (!userHandle) throw badRequest()
  if (await users.get<User>(userHandle)) { throw conflict() }

  const options = await f2l.attestationOptions() as any;
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

  const options = await f2l.assertionOptions() as any;
  options.allowCredentials = getAllowCredentials(user),

  session.userHandle = userHandle
  session.challenge = options.challenge

  return new JSONResponse(Structured.toJSON(options))
})


router.post('/response', combine(sessionMW, jsonMW), async (req, { session, body }) => {
  const data = Structured.fromJSON(body)
  // console.log(data)

  if (!session.userHandle) throw unauthorized();

  if (data.response.attestationObject != null) {
    // /register
    const reg = await f2l.attestationResult(data, {
      challenge: session.challenge as any,
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

    await users.set(user.name, user)
    session.loggedIn = true
    delete session.userId
    delete session.challenge;

    return ok()
  } 
  else if (data.response.authenticatorData != null) {
    // /login
    const user = await users.get<User>(session.userHandle)
    if (!user) throw unauthorized()

    const authr = user.authenticators.find(x => compareBufferSources(x.credId, data.rawId))
    if (!authr) throw unauthorized();

    const reg = await f2l.assertionResult(data, {
      allowCredentials: getAllowCredentials(user),
      challenge: session.challenge as any,
      origin: location.origin,
      factor: "either",
      publicKey: authr.credentialPublicKeyPem,
      prevCounter: authr.counter,
      userHandle: user.id,
    })
    if (!reg.authnrData) throw unauthorized();
    console.log(reg)

    authr.counter = reg.authnrData.get('counter');

    await users.set(session.userHandle, user)
    session.loggedIn = true
    delete session.challenge;

    return ok()
  }

  return badRequest()
})

router.post('/logout', sessionMW, (req, { session }) => {
  session.loggedIn = false;
  delete session.userHandle;
  return ok()
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

router.addEventListener('error', ev => console.warn(ev))

router.get('/favicon.ico', () => ok())
