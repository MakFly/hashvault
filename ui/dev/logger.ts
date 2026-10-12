import { formatLogLine, logEnabled, makeRecord, type LogFields, type LogLevel } from "../shared/logging"

/** Same environment switches and terminal behavior as Tanship's server logger. */
export function createLogger(scope: string) {
  const minimum = process.env.LOG_LEVEL || (process.env.NODE_ENV === "production" ? "info" : "debug")
  const pretty = (process.env.LOG_FORMAT || (process.env.NODE_ENV === "production" ? "json" : "pretty")) === "pretty"
  function emit(level: LogLevel, fields: LogFields, msg: string) {
    if (!logEnabled(level, minimum)) return
    const record = makeRecord(scope, level, fields, msg)
    process.stdout.write((pretty ? formatLogLine(record, process.env.NO_COLOR === undefined) : JSON.stringify(record)) + "\n")
  }
  return Object.fromEntries((["debug", "info", "warn", "error"] as const).map(level => [level, (fields: LogFields, msg: string) => emit(level, fields, msg)])) as Record<LogLevel, (fields: LogFields, msg: string) => void>
}

export const log = createLogger("web")
