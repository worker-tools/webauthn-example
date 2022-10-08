# Workers WebAuthn Example

Example project for passwordless login through WebAuthn in [Worker Runtimes](https://workers.js.org) built with [Worker Tools](https://workers.tools)

## Usage
### Deno
Requires Deno 1.22 or higher.

```sh
deno task serve
```

This will store sessions and users in a SQLite file at the root. 

### Cloudflare Workers
If you have [Miniflare](https://miniflare.dev) installed, just run

```sh
miniflare
```

If you have wrangler 2 or later installed, run

```sh
wrangler dev --local
```

For running on CF Workers proper,
get your CF `account_id` from the workers dashboard and overwrite in `wrangler.toml`.
Create a new KV namespace on the workers dashboard and overwrite `id` and `preview_id`:

```toml
account_id = '...'
kv_namespaces = [ 
  { binding = "KV_STORAGE", id = "...", preview_id = "..." }
]
```

Then run

```sh
wrangler dev
```

If you want to run on a other port than 8787, update `WORKER_LOCATION` in `wrangler.toml`, otherwise WebAuthn calls will fail.
