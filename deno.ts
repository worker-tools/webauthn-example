import { serve } from "https://deno.land/std@0.141.0/http/server.ts";

import 'https://ghuc.cc/worker-tools/deno-kv-storage/adapters/sqlite.ts'
// import 'https://ghuc.cc/worker-tools/deno-kv-storage/adapters/postgres.ts'

import { router } from './index.ts'

serve(router.serveCallback, { port: Number(location.port) })

