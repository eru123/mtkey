/// <reference types="vite/client" />

declare global {
  interface Window {
    /** Present only inside a Tauri webview; guards native-only calls. */
    __TAURI_INTERNALS__?: unknown
  }
}

export {}
