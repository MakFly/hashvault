export type LogLevel = "debug" | "info" | "warn" | "error"
export type LogFields = Record<string, unknown>
export type LogRecord = LogFields & { level: LogLevel; time: string; scope: string; msg: string }
export const LOG_REDACT_KEYS = ["authorization", "cookie", "set-cookie", "headers", "password", "newPassword", "currentPassword", "token", "accessToken", "refreshToken", "idToken", "sessionToken", "access_token", "refresh_token", "secret", "clientSecret", "secretValue", "value", "body", "response", "credentials", "signature", "nonce", "launch", "privateKey", "apiKey", "email", "to", "otp"] as const
const sensitive = new Set(LOG_REDACT_KEYS.map(key => key.toLowerCase()))
const ranks: Record<LogLevel, number> = { debug: 20, info: 30, warn: 40, error: 50 }
const clean = (value: string, limit: number) => Array.from(value.slice(0, limit)).map(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127 ? " " : char).join("")

export function safePath(value: string): string {
  return clean(value.split(/[?#]/, 1)[0], 256).replace(/[^/\s]*@[^/\s]*/g, "[redacted]")
}

export function errorType(error: unknown): string {
  return error instanceof Error && ["Error", "TypeError", "SyntaxError", "RangeError", "AbortError", "ApiError"].includes(error.name) ? error.name : "Error"
}

/** Never serialize an Error's message or stack: either can contain a secret value. */
export function redact(value: unknown, seen = new WeakSet<object>(), depth = 0): unknown {
  if (typeof value === "string") return clean(value, 512).replace(/[^\s<>]+@[^\s<>]+/g, "[redacted]")
  if (value === null || typeof value === "number" || typeof value === "boolean") return value
  if (typeof value !== "object") return undefined
  if (value instanceof Error) return { type: errorType(value) }
  if (depth >= 5 || seen.has(value)) return "[omitted]"
  seen.add(value)
  if (Array.isArray(value)) return value.slice(0, 20).map(item => redact(item, seen, depth + 1))
  return Object.fromEntries(Object.entries(value).slice(0, 32).map(([key, item]) => [key, sensitive.has(key.toLowerCase()) ? "[redacted]" : key === "path" && typeof item === "string" ? safePath(item) : redact(item, seen, depth + 1)]))
}

export function logEnabled(level: LogLevel, minimum: string): boolean {
  if (minimum === "silent") return false
  return ranks[level] >= (ranks[minimum as LogLevel] ?? ranks.info)
}

export function makeRecord(scope: string, level: LogLevel, fields: LogFields, msg: string): LogRecord {
  return { ...redact(fields) as LogFields, level, time: new Date().toISOString(), scope, msg }
}

/** Tanship's aligned time/scope/request columns, without a trailing JSON blob. */
export function formatLogLine(record: LogRecord, color = true): string {
  const paint = (code: string, value: string) => color ? `\x1b[${code}m${value}\x1b[0m` : value
  const subdued = record.scope === "web" && typeof record.status === "number" && record.status < 400
  const tone = (code: string, value: string) => paint(subdued ? "90" : code, value)
  const at = new Date(record.time)
  const clock = at.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(at.getMilliseconds()).padStart(3, "0")
  const levelColor = { debug: "34", info: "32", warn: "33", error: "31" }[record.level]
  const consumed = new Set(["level", "time", "scope", "msg", "method", "path", "status", "ms"])
  let body = record.msg
  if (typeof record.method === "string" && typeof record.path === "string") {
    const status = typeof record.status === "number" ? record.status : undefined
    body = `${tone("1", record.method.padEnd(6))} ${tone("37", record.path.padEnd(42))} ${tone(status && status >= 500 ? "31" : status && status >= 400 ? "33" : "32", String(status ?? "---"))} ${tone("90", `${record.ms ?? "?"}ms`.padStart(7))}`
  }
  const fields = Object.entries(record).filter(([key, value]) => !consumed.has(key) && value !== undefined)
    .map(([key, value]) => `${key}=${typeof value === "string" && !/[\s="]/.test(value) ? value : JSON.stringify(value)}`).join(" ")
  return `${paint("90", clock)} ${paint(levelColor, record.level.toUpperCase().padEnd(5))} ${tone("35", record.scope.padEnd(9))} ${body}${fields ? "  " + paint("90", fields) : ""}`
}
