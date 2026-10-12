import { ServerResponse } from "node:http"
import type { Plugin, ProxyOptions } from "vite"
import { log } from "./logger"
import { safePath, type LogFields, type LogLevel } from "../shared/logging"

export function bridgeProxy(target: string): ProxyOptions {
  return {
    target, changeOrigin: true,
    configure(proxy) {
      // Vite's default proxy failure is an empty 500. Send a JSON diagnosis
      // first so API requests can never fall through to the SPA index.
      proxy.prependListener("error", (_error, _req, response) => {
        if (response instanceof ServerResponse && !response.headersSent) {
          response.writeHead(503, { "Content-Type": "application/json", "Cache-Control": "no-store" })
          response.end(JSON.stringify({ error: "The local API bridge is unavailable. Restart with make stop, then make dev, and reload this page." }))
        }
      })
    },
  }
}

export function frontendLogging(): Plugin {
  return {
    name: "hashvault-frontend-logging", apply: "serve",
    configureServer(server) {
      server.httpServer?.once("listening", () => log.info({ port: server.config.server.port, apiUrl: server.config.server.proxy?.["/api"] && typeof server.config.server.proxy["/api"] === "object" ? String(server.config.server.proxy["/api"].target) : undefined }, "web server ready"))
      server.ws.on("hashvault:log", (input: unknown) => {
        if (!input || typeof input !== "object") return
        const record = input as Record<string, unknown>
        const level = record.level
        if (!["debug", "info", "warn", "error"].includes(String(level))) return
        // Browser logging is untrusted input. Admit only bounded diagnostic
        // metadata and fixed messages, never arbitrary strings from exceptions.
        const messages = ["http request", "browser runtime error", "unhandled promise rejection", "route failed", "browser session failed", "web client ready"]
        if (!messages.includes(String(record.msg))) return
        const fields: LogFields = {}
        for (const key of ["method", "status", "ms", "requestId", "errorCode", "errorType", "event", "line", "column"]) {
          const value = record[key]
          if (typeof value === "number" && Number.isFinite(value)) fields[key] = value
          else if (typeof value === "string" && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value)) fields[key] = value
        }
        if (typeof record.path === "string") fields.path = safePath(record.path)
        log[level as LogLevel](fields, String(record.msg))
      })
    },
  }
}
