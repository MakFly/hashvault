import { NavLink, Outlet, useLoaderData, useLocation, useNavigation, useRevalidator } from "react-router"
import { CircleCheck, Fingerprint, KeyRound, Layers3, LockKeyhole, RefreshCw, Server, ShieldCheck } from "lucide-react"
import { request, type Session, type Status } from "./api/client"
import { Button } from "./components/ui/button"
import { Feedback } from "./components/shared"
import { useState } from "react"

export async function layoutLoader() {
  const status = await request<Status>("/v1/sys/status")
  let session: Session | null = null
  if (!status.sealed) { try { session = await request<Session>("/v1/auth/session") } catch { /* Authentication can be renewed from the operator CLI. */ } }
  return { status, session }
}

const links = [{ path: "/secrets", title: "Secrets", Icon: KeyRound }, { path: "/deployments", title: "Deployments", Icon: Layers3 }, { path: "/targets", title: "Targets", Icon: Server }, { path: "/access", title: "Access", Icon: Fingerprint }, { path: "/audit", title: "Audit", Icon: ShieldCheck }]

export function Layout() {
  const { status, session } = useLoaderData<typeof layoutLoader>()
  const location = useLocation()
  const navigation = useNavigation()
  const revalidator = useRevalidator()
  const [message, setMessage] = useState("")
  const [sealing, setSealing] = useState(false)
  async function seal() {
    setSealing(true); setMessage("")
    try { await request("/v1/sys/seal", { method: "POST" }); revalidator.revalidate() } catch (error) { setMessage(error instanceof Error ? error.message : "Could not seal the vault.") } finally { setSealing(false) }
  }
  return <div className="app-layout">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar"><div className="brand"><span className="brand-mark"><LockKeyhole size={21} aria-hidden="true" /></span>hashvault</div>
      <nav aria-label="Main navigation">{links.map(({ path, title, Icon }) => <NavLink key={path} to={path + location.search} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}><Icon size={19} aria-hidden="true" />{title}</NavLink>)}</nav>
      <p className="mt-8 hidden text-xs leading-relaxed text-muted-foreground lg:block">One vault.<br />Explicit versions.<br />Traceable releases.</p>
    </aside>
    <div className="workspace"><header className="topbar"><div className="flex flex-wrap items-center gap-3"><span className="text-sm font-medium">{status.vault}</span><span className={`status ${status.sealed ? "sealed" : "ready"}`}>{status.sealed ? <LockKeyhole size={13} aria-hidden="true" /> : <CircleCheck size={13} aria-hidden="true" />}{status.sealed ? "Sealed" : "Unsealed"}</span></div>
      <div className="flex flex-wrap items-center gap-2"><span className="text-sm text-muted-foreground">{session?.principal || "No active vault session"}</span><Button variant="ghost" onClick={() => revalidator.revalidate()} disabled={revalidator.state !== "idle"} aria-label="Refresh vault status"><RefreshCw /></Button>{session && !status.sealed && <Button variant="secondary" onClick={seal} disabled={sealing}>{sealing ? "Sealing…" : "Seal vault"}</Button>}</div>
    </header><main id="main-content" className="main-content" aria-busy={navigation.state !== "idle"}><Feedback message={message} error />
      {status.sealed ? <Feedback message="The vault is sealed. Existing prepared releases keep working. Unseal the vault from your terminal to manage secrets." /> : !session ? <Feedback message="Authenticate with hashvault login in your terminal, then use Refresh. Your private key stays outside the browser." /> : null}
      <Outlet context={{ available: !status.sealed && !!session }} />
    </main></div>
  </div>
}
