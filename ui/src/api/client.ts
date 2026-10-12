import type { components } from "./schema"

export type Preparation = components["schemas"]["Preparation"]
export type Publication = components["schemas"]["Publication"]
export type Target = components["schemas"]["Target"]
export type Principal = components["schemas"]["Principal"]
export type Status = components["schemas"]["Status"]
export type Session = components["schemas"]["Session"]
export type Manifest = components["schemas"]["Manifest"]

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, { ...options, credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json", ...options.headers } })
  const text = await response.text()
  if (!response.ok) {
    let message = response.status === 403 ? "Your account is not allowed to perform this action." : response.status === 401 ? "Your vault session expired. Run hashvault login, then refresh." : response.status === 503 ? "The vault is sealed or unavailable. Unseal it from your terminal, then refresh." : "The request could not be completed."
    try { const body = JSON.parse(text) as { error?: string }; if (body.error && ![401, 403, 503].includes(response.status)) message = body.error } catch { /* The local bridge may return a plain-text connection error. */ }
    throw new ApiError(response.status, message)
  }
  return (text ? JSON.parse(text) : null) as T
}

export const pathPart = (value: string) => encodeURIComponent(value)
export const secretPath = (env: string, app: string, key?: string) => `/v1/secrets/${pathPart(env)}/${pathPart(app)}${key ? `/${pathPart(key)}` : ""}`

export function encodeValue(value: string) {
  const bytes = new TextEncoder().encode(value)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  bytes.fill(0)
  return btoa(binary)
}

export function decodeValue(value: string) {
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0))
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes) } finally { bytes.fill(0) }
}

export function saveDescriptor(preparation: Preparation) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(preparation, null, 2)], { type: "application/json" }))
  const link = document.createElement("a")
  link.href = url; link.download = `hashvault-${preparation.id}.json`; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function initializeBrowserSession() {
  const nonce = new URLSearchParams(window.location.hash.slice(1)).get("launch")
  if (!nonce) return
  history.replaceState(null, "", window.location.pathname + window.location.search)
  const response = await fetch("/session", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ nonce }) })
  if (!response.ok) throw new Error("This launch link expired. Restart hashvault ui and open the new link.")
}
