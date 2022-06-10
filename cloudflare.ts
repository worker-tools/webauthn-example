import '@worker-tools/location-polyfill'
import { router } from "./index.ts"
self.addEventListener('fetch', router)