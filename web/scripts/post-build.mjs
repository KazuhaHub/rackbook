// vite empties dist/ on every build; recreate the placeholder the Go embed expects.
import { writeFileSync } from 'node:fs'
writeFileSync(new URL('../dist/.gitkeep', import.meta.url), '')
