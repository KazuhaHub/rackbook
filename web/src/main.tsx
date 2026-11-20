import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { reloadForStaleChunk } from './lib/staleChunk.ts'
import { bootLocale, chooseLocale } from './lib/locale.ts'
import { normalizeLocale } from './i18n/index.ts'

// Vite fires this when a chunk (or its CSS) from an older build is gone.
// preventDefault stops the error only when a reload was started; otherwise the
// import fails and the error page asks the user to refresh.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadForStaleChunk()) event.preventDefault()
})

// scripts/check-i18n-dom.mts switches the language the way the menu does, without clicking through it.
if (import.meta.env.DEV) {
  ;(window as unknown as Record<string, unknown>).__rbChooseLocale = (l: string) => {
    const n = normalizeLocale(l)
    return n ? chooseLocale(n, false) : Promise.reject(new Error(`unsupported ${l}`))
  }
}

// Start in the language this browser chose before, so the first paint is in it.
void bootLocale().finally(() =>
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  ),
)
