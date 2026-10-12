import { errorType, formatLogLine, logEnabled, makeRecord, safePath, type LogFields, type LogLevel } from "../../shared/logging"

const minimum = import.meta.env.DEV ? "debug" : "info"

/** Browser-safe equivalent of Tanship's scoped web logger. No Node/Pino bundle. */
export function createLogger(scope: string) {
  function emit(level: LogLevel, fields: LogFields, msg: string) {
    if (!logEnabled(level, minimum)) return
    const record = makeRecord(scope, level, fields, msg)
    if (import.meta.env.DEV) {
      const css = { debug: "#2563eb", info: "#16803a", warn: "#a16207", error: "#dc2626" }[level]
      if (import.meta.env.VITE_NO_COLOR !== undefined) console[level](formatLogLine(record, false))
      else console[level]("%c" + formatLogLine(record, false), `color:${css}`)
      // Vite only receives sanitized metadata. Secret values and response bodies
      // never cross this logging channel. Production has no HMR transport.
      import.meta.hot?.send("hashvault:log", record)
    } else console[level](JSON.stringify(record))
  }
  return Object.fromEntries((["debug", "info", "warn", "error"] as const).map(level => [level, (fields: LogFields, msg: string) => emit(level, fields, msg)])) as Record<LogLevel, (fields: LogFields, msg: string) => void>
}

export const log = createLogger("web")

export function installErrorLogging() {
  const onError = (event: ErrorEvent) => log.error({ event: "window.error", errorType: errorType(event.error), path: safePath(event.filename), line: event.lineno, column: event.colno }, "browser runtime error")
  const onRejection = (event: PromiseRejectionEvent) => log.error({ event: "unhandledrejection", errorType: errorType(event.reason) }, "unhandled promise rejection")
  window.addEventListener("error", onError)
  window.addEventListener("unhandledrejection", onRejection)
  const cleanup = () => { window.removeEventListener("error", onError); window.removeEventListener("unhandledrejection", onRejection) }
  import.meta.hot?.dispose(cleanup)
  return cleanup
}
