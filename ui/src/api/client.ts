import type { components } from "./schema"
import { log } from "../lib/logger"
import { safePath } from "../../shared/logging"

export type Preparation = components["schemas"]["Preparation"]
export type Publication = components["schemas"]["Publication"]
export type Target = components["schemas"]["Target"]
export type Principal = components["schemas"]["Principal"]
export type Status = components["schemas"]["Status"]
export type Session = components["schemas"]["Session"]
export type Manifest = components["schemas"]["Manifest"]

export class ApiError extends Error {
  constructor(public status: number, message: string, public code = "http_error", public requestId?: string) { super(message); this.name = "ApiError" }
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const started = performance.now()
  const requestId = crypto.randomUUID()
  const method = options.method || "GET"
  let response: Response | undefined, failure: string | undefined
  try {
    const headers = new Headers(options.headers)
    headers.set("Accept", "application/json")
    headers.set("Content-Type", "application/json")
    headers.set("X-Request-Id", requestId)
    response = await fetch(`/api${path}`, { ...options, credentials: "same-origin", cache: "no-store", headers })
    const text = await response.text()
    if (!response.ok) {
      let message = response.status === 403 ? "Your account is not allowed to perform this action." : response.status === 401 ? import.meta.env.DEV ? "The local session is unavailable. Restart with make stop, then make dev, and reload this page." : "Open the launch link printed by hashvault ui, and authenticate with hashvault login." : response.status === 503 ? import.meta.env.DEV ? "The local vault is unavailable. Check the make dev terminal." : "The vault or local API bridge is unavailable. Check your SSH tunnel and vault status." : "The request could not be completed."
      try { const body = JSON.parse(text) as { error?: string }; if (typeof body.error === "string" && ![401, 403].includes(response.status)) message = body.error } catch { /* No response content is logged. */ }
      throw new ApiError(response.status, message, "http_error", requestId)
    }
    if (response.status === 204) return null as T
    const type = response.headers.get("Content-Type") || ""
    if (!/^application\/(?:json|[\w.-]+\+json)(?:\s*;|$)/i.test(type)) {
      throw new ApiError(502, "The API returned a page instead of JSON. Restart with make stop, then make dev, and reload this page.", "non_json_response", requestId)
    }
    try { return JSON.parse(text) as T }
    catch { throw new ApiError(502, "The API returned an invalid JSON response. Check the local API bridge.", "invalid_json_response", requestId) }
  } catch (error) {
    failure = error instanceof ApiError ? error.code : error instanceof Error && error.name === "AbortError" ? "request_aborted" : "network_error"
    if (error instanceof ApiError) throw error
    throw new ApiError(503, "The API could not be reached. Check your SSH tunnel and local bridge.", failure, requestId)
  } finally {
    const fields = { method, path: safePath(`/api${path}`), status: response?.status, ms: Math.round(performance.now() - started), requestId, ...(failure ? { errorCode: failure } : {}) }
    if (failure && failure !== "http_error" && failure !== "request_aborted" || (response?.status || 0) >= 500) log.error(fields, "http request")
    else if (failure || (response?.status || 0) >= 400) log.warn(fields, "http request")
    else log.debug(fields, "http request")
  }
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
  if (!nonce && !import.meta.env.DEV) return
  if (nonce) history.replaceState(null, "", window.location.pathname + window.location.search)
  const response = await fetch("/session", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ nonce }) })
  if (!response.ok) throw new Error("This launch link expired or the API bridge is unavailable. Restart make dev or hashvault ui and open its new link.")
}
