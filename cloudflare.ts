import '@worker-tools/location-polyfill'
import { router } from "./index.ts"
addEventListener('fetch', router)