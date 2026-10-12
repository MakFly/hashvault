import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter, Navigate, RouterProvider, useRouteError } from "react-router"
import { initializeBrowserSession } from "./api/client"
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
  return <div className="mx-auto max-w-xl p-8"><h1 className="page-title">Connect to your vault</h1><p className="page-intro" role="alert">{error instanceof Error ? error.message : "The vault could not be reached."}</p><p className="mt-5 text-sm leading-relaxed text-muted-foreground">Keep your SSH tunnel open and authenticate with <code>hashvault login</code>. Then reload this page.</p><button className="mt-6 min-h-11 rounded-lg bg-primary px-5 text-primary-foreground" onClick={() => window.location.reload()}>Retry connection</button></div>
}

async function start() {
  const root = createRoot(document.getElementById("root")!)
  try { await initializeBrowserSession() }
  catch (error) { root.render(<div className="mx-auto max-w-xl p-8"><h1 className="page-title">Open a new session</h1><p className="page-intro" role="alert">{error instanceof Error ? error.message : "The launch link could not be used."}</p></div>); return }
  const router = createBrowserRouter([{ path: "/", element: <Layout />, loader: layoutLoader, errorElement: <ConnectionError />, children: [
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
void start()
