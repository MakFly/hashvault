import { StrictMode, useEffect, useRef } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter, Navigate, RouterProvider, useRouteError } from "react-router"
import { ApiError, initializeBrowserSession } from "./api/client"
import { installErrorLogging, log } from "./lib/logger"
import { errorType, safePath } from "../shared/logging"
import { Pending } from "./components/shared"
import { Layout, layoutLoader } from "./layout"
import { SecretsPage, secretAction, secretsLoader } from "./pages/secrets"
import { DeploymentsPage, deploymentAction, deploymentsLoader } from "./pages/deployments"
import { TargetsPage, targetAction, targetsLoader } from "./pages/targets"
import { AccessPage, accessAction, accessLoader } from "./pages/access"
import { AuditPage, auditAction } from "./pages/audit"
import "@fontsource/ibm-plex-sans/400.css"
import "@fontsource/ibm-plex-sans/500.css"
import "@fontsource/ibm-plex-sans/600.css"
import "./styles.css"

function ConnectionError() {
  const error = useRouteError()
  const reported = useRef<unknown>(null)
  useEffect(() => {
    if (reported.current === error) return
    reported.current = error
    const level = error instanceof ApiError && error.status < 500 ? "warn" : "error"
    log[level]({ errorType: errorType(error), path: safePath(window.location.pathname), ...(error instanceof ApiError ? { status: error.status, errorCode: error.code, requestId: error.requestId } : {}) }, "route failed")
  }, [error])
  return <div className="mx-auto max-w-xl p-8"><h1 className="page-title">Connect to your vault</h1><p className="page-intro" role="alert">{error instanceof Error ? error.message : "The vault could not be reached."}</p><p className="mt-5 text-sm leading-relaxed text-muted-foreground">{import.meta.env.DEV ? <>Restart the local vault with <code>make stop</code>, then <code>make dev</code>. Reload this page.</> : <>Keep your SSH tunnel open and authenticate with <code>hashvault login</code>. Then reload this page.</>}</p><button className="mt-6 min-h-11 rounded-lg bg-primary px-5 text-primary-foreground" onClick={() => window.location.reload()}>Retry connection</button></div>
}

async function start() {
  const root = createRoot(document.getElementById("root")!)
  try { await initializeBrowserSession() }
  catch (error) {
    log.warn({ errorType: errorType(error) }, "browser session failed")
    if (!import.meta.env.DEV) {
      root.render(<div className="mx-auto max-w-xl p-8"><h1 className="page-title">Open a new session</h1><p className="page-intro" role="alert">{error instanceof Error ? error.message : "The launch link could not be used."}</p></div>); return
    }
  }
  const router = createBrowserRouter([{ path: "/", element: <Layout />, loader: layoutLoader, HydrateFallback: () => <div className="p-8"><Pending /></div>, errorElement: <ConnectionError />, children: [
    { index: true, element: <Navigate to="/secrets" replace /> },
    { path: "secrets", element: <SecretsPage />, loader: secretsLoader, action: secretAction },
    { path: "deployments", element: <DeploymentsPage />, loader: deploymentsLoader, action: deploymentAction },
    { path: "targets", element: <TargetsPage />, loader: targetsLoader, action: targetAction },
    { path: "access", element: <AccessPage />, loader: accessLoader, action: accessAction },
    { path: "audit", element: <AuditPage />, action: auditAction },
    { path: "*", element: <div><h1 className="page-title">Page not found</h1><p className="page-intro">Use the navigation to return to your vault.</p></div> },
  ] }])
  root.render(<StrictMode><RouterProvider router={router} /></StrictMode>)
}
installErrorLogging()
log.info({ path: safePath(window.location.pathname) }, "web client ready")
void start()
