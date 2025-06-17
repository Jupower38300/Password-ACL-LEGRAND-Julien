import { serve } from '@hono/node-server'
import App from './index.js'

const port = 3000
console.log(`Server is running on http://localhost:${port}`)


serve({
  fetch: App.fetch,
  port
})

