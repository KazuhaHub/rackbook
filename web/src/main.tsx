import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { reloadForStaleChunk } from './lib/staleChunk.ts'

// Vite fires this when a chunk (or its CSS) from an older build is gone.
// preventDefault stops the error only when a reload was started; otherwise the
// import fails and the error page asks the user to refresh.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadForStaleChunk()) event.preventDefault()
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
