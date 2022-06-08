# Workers WebAuthn Example

Example project for password-less login through WebAuthn in Cloudflare Workers and Deno.

## Usage
### Deno
Requires Deno 1.22 or higher.

```sh
deno task serve
```

This will store sessions and users in a SQLite file at the root. 

### Workers
Requires wrangler 2.

Get your CF `account_id` from the workers dashboard and overwrite in `wrangler.toml`.
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

NOTE: `wrangler dev --local` is currently not supported due to inconsistency in web crypto implementation.
