import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import { fileURLToPath } from "node:url"
import { bridgeProxy, frontendLogging } from "./dev/logging"

const bridge = new URL(process.env.HASHVAULT_UI_BRIDGE || "http://127.0.0.1:8822")
if (bridge.protocol !== "http:" || bridge.hostname !== "127.0.0.1" || bridge.username || bridge.password || bridge.pathname !== "/" || bridge.search || bridge.hash) throw new Error("HASHVAULT_UI_BRIDGE must be a local HTTP bridge origin")

export default defineConfig({
  plugins: [react(), tailwindcss(), frontendLogging()],
  clearScreen: false,
  server: {
    host: "127.0.0.1", port: 4322, strictPort: true,
    proxy: { "/api": bridgeProxy(bridge.origin), "/session": bridgeProxy(bridge.origin) },
  },
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
})
