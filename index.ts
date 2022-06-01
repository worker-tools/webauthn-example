// deno-lint-ignore-file no-explicit-any no-unused-vars require-await ban-unused-ignore
import { WorkerRouter } from '@worker-tools/router'
import { combine, plainCookies, storageSession, accepts, bodyParser, contentTypes, FORM, FORM_DATA } from '@worker-tools/middleware';
import { html, HTMLResponse } from '@worker-tools/html'
import { StorageArea } from '@worker-tools/kv-storage';
import { ok, forbidden, unauthorized, badRequest, conflict } from '@worker-tools/response-creators';
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
  authenticators: Map<any,any>[],
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
  storageSession<Session>({ 
    defaultSession: { loggedIn: false }, 
    storage: new StorageArea('session') 
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

router.addEventListener('error', ev => console.warn(ev))

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
const script = html`
  <script type="module">
    import { JSONRequest } from 'https://cdn.skypack.dev/@worker-tools/json-fetch'
    import * as Structured from 'https://cdn.skypack.dev/@worker-tools/structured-json'

    // Sadly, this is necessary to stringify WebAuthn credentials...
    function credToJSON(x) {
      if (x instanceof ArrayBuffer) return x
      if (Array.isArray(x)) {
        const arr = [];
        for (const i of x) arr.push(credToJSON(i));
        return arr
      }
      if (x != null && typeof x === 'object') {
        const obj = {};
        for (const key in x)
          if (typeof x[key] !== 'function')
            obj[key] = credToJSON(x[key])
        return obj
      }
      return x
    }

    const form = document.querySelector('form');
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (ev.submitter.formAction.endsWith('/register')) {
        const res = await fetch('/register', { method: 'POST', body: new FormData(form) });
        if (res.ok) {
          const publicKey = Structured.fromJSON(await res.json());
          const cred = await navigator.credentials.create({ publicKey });
          const body = Structured.toJSON(credToJSON(cred));
          const res2 = await fetch(new JSONRequest('/response', { method: 'POST', body }));
          if (res2.ok) location.reload()
        }
      }
      else if (ev.submitter.formAction.endsWith('/login')) {
        const res = await fetch('/login', { method: 'POST', body: new FormData(form) });
        if (res.ok) {
          const publicKey = Structured.fromJSON(await res.json());
          const cred = await navigator.credentials.get({ publicKey });
          const body = Structured.toJSON(credToJSON(cred));
          const res2 = await fetch(new JSONRequest('/response', { method: 'POST', body }));
          if (res2.ok) location.reload()
        }
      }
      else if (ev.submitter.formAction.endsWith('/logout')) {
        const res = await fetch('/logout', { method: 'POST' });
        if (res.ok) location.reload()
      }
    })
  </script>
`

router.get('/', sessionMW, (req, { session }) => {
  return new HTMLResponse(html`<html>
<body>
  ${style}
  <form method="POST">
  ${session.loggedIn 
    ? html`<p>Hello, ${session.userHandle}.</p><button type="submit" formaction="/logout">Logout</button>`
    : html`<div>
      <input type="text" name="user-handle" />
      <button type="submit" formaction="/register">Register</button>
      <button type="submit" formaction="/login">Login</button>
    </div>`}
  </form>
  ${script}
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
  id: authr.get('credId'),
  transports: authr.get('transports'),
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
  console.log(data)

  if (!session.userHandle) throw forbidden();

  if (data.response.attestationObject != null) {
    // /register
    const reg = await f2l.attestationResult(data, {
      challenge: session.challenge as any,
      origin: location.origin,
      factor: "either"
    })
    if (!reg.authnrData) throw unauthorized();

    const user = {
      id: session.userId,
      name: session.userHandle,
      displayName: session.userHandle,
      authenticators: [reg.authnrData],
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

    const authr = user.authenticators.find(x => compareBufferSources(x.get('credId'), data.rawId))
    if (!authr) throw unauthorized();

    const reg = await f2l.assertionResult(data, {
      allowCredentials: getAllowCredentials(user),
      challenge: session.challenge as any,
      origin: location.origin,
      factor: "either",
      publicKey: authr.get('credentialPublicKeyPem'),
      prevCounter: authr.get('counter'),
      userHandle: user.id,
    })
    if (!reg.authnrData) throw unauthorized();

    authr.set('counter', reg.authnrData.get('counter')) 

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
      }, { status, statusText })
    }
    return new HTMLResponse(html`<html>
      <body>
        ${style}
        Something went wrong: ${status} ${statusText} ${message}
      </body>
    </html>`, { status, statusText })
  },
)

router.get('/favicon.ico', () => ok())
