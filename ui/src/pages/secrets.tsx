import { useEffect, useRef, useState } from "react"
import { useFetcher, useLoaderData, useOutletContext, type ActionFunctionArgs, type LoaderFunctionArgs } from "react-router"
import { Eye, EyeOff, History, KeyRound, Plus } from "lucide-react"
import { ApiError, decodeValue, encodeValue, request, secretPath } from "@/api/client"
import { Empty, Feedback, PageHeader, Pending, Scope, scopeFromURL } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Dialog } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export async function secretsLoader({ request: req }: LoaderFunctionArgs) {
  const scope = scopeFromURL(req.url)
  if (!scope.app) return { ...scope, keys: [] as string[], error: "" }
  try { const data = await request<{ keys: string[] }>(secretPath(scope.env, scope.app)); return { ...scope, keys: data.keys || [], error: "" } }
  catch (error) { return { ...scope, keys: [] as string[], error: error instanceof ApiError && error.status === 404 ? "" : error instanceof Error ? error.message : "Could not load secrets." } }
}

export async function secretAction({ request: req }: ActionFunctionArgs) {
  const form = await req.formData()
  const env = String(form.get("env")), app = String(form.get("app")), key = String(form.get("key"))
  const value = encodeValue(String(form.get("value") || "")); form.delete("value")
  try { const result = await request<{ version: number }>(secretPath(env, app, key), { method: "PUT", body: JSON.stringify({ value }) }); return { ok: true, message: `${key} saved as version ${result.version}. Existing deployments keep their pinned versions.` } }
  catch (error) { return { ok: false, message: error instanceof Error ? error.message : "Could not save the secret." } }
}

export function SecretsPage() {
  const { keys, env, app, error } = useLoaderData<typeof secretsLoader>()
  const { available } = useOutletContext<{ available: boolean }>()
  const fetcher = useFetcher<typeof secretAction>()
  const [editor, setEditor] = useState<string | null>(null)
  const [historyKey, setHistoryKey] = useState<string | null>(null)
  const [versions, setVersions] = useState<{ version: number; destroyed: boolean }[]>([])
  const [historyError, setHistoryError] = useState("")
  const [revealed, setRevealed] = useState<string | null>(null)
  const [reading, setReading] = useState(false)
  const readSequence = useRef(0)
  useEffect(() => { if (fetcher.state === "idle" && fetcher.data?.ok) setEditor(null) }, [fetcher.state, fetcher.data])
  useEffect(() => { if (revealed === null) return; const timer = setTimeout(() => setRevealed(null), 30000); return () => clearTimeout(timer) }, [revealed])
  useEffect(() => { readSequence.current++; setRevealed(null); setHistoryKey(null); setEditor(null); setReading(false); return () => { readSequence.current++ } }, [env, app])
  async function showHistory(key: string) {
    const sequence = ++readSequence.current
    setHistoryKey(key); setVersions([]); setHistoryError(""); setRevealed(null); setReading(false)
    try { const result = await request<{ versions: typeof versions }>(secretPath(env, app, key) + "/versions"); if (sequence === readSequence.current) setVersions(result.versions) } catch (error) { if (sequence === readSequence.current) setHistoryError(error instanceof Error ? error.message : "Could not load versions.") }
  }
  async function reveal(version: number) {
    if (!historyKey) return
    const sequence = ++readSequence.current
    setReading(true); setRevealed(null); setHistoryError("")
    try { const result = await request<{ value: string }>(secretPath(env, app, historyKey) + `?version=${version}`); if (sequence === readSequence.current) setRevealed(decodeValue(result.value)) }
    catch (error) { if (sequence === readSequence.current) setHistoryError(error instanceof Error ? error.message : "This value could not be read as text. Use the CLI for binary secrets.") }
    finally { if (sequence === readSequence.current) setReading(false) }
  }
  return <>
    <PageHeader title="Secrets" description="Store values once. Every change creates a version; deployments choose which one they use."><Button onClick={() => setEditor("")} disabled={!available || !app}><Plus />Add secret</Button></PageHeader>
    <Scope /><Feedback message={error} error /><Feedback message={fetcher.state === "idle" ? fetcher.data?.message : undefined} error={fetcher.data?.ok === false} />
    <div className="surface">{keys.length ? keys.map(key => <div className="record" key={key}><div className="record-main"><h2 className="record-title secret-key flex items-center gap-3"><KeyRound className="size-4 shrink-0 text-primary" aria-hidden="true" />{key}</h2><p className="record-meta">Value hidden. Read access is checked separately.</p></div><div className="flex flex-wrap gap-2"><Button variant="ghost" onClick={() => showHistory(key)} disabled={!available}><History />Versions</Button><Button variant="secondary" onClick={() => setEditor(key)} disabled={!available}>New version</Button></div></div>) : <Empty title={app ? "No secrets in this application" : "Choose an application"}>{app ? "Add your first secret or import a dotenv file with the CLI." : "Enter the environment and application above to open their secrets."}</Empty>}</div>
    <Dialog open={editor !== null} onOpenChange={open => { if (!open) setEditor(null) }} title={editor ? "Create a new version" : "Add a secret"} description="The value is stored in the vault. Running services keep using their current version until you deploy or publish.">
      <fetcher.Form method="post" className="form-grid"><input type="hidden" name="env" value={env} /><input type="hidden" name="app" value={app} /><div><Label htmlFor="secret-key">Secret name</Label><Input id="secret-key" name="key" required pattern="[A-Z][A-Z0-9_]{0,127}" defaultValue={editor || ""} readOnly={!!editor} placeholder="DATABASE_URL" autoComplete="off" /></div><div><Label htmlFor="secret-value">Value</Label><Input id="secret-value" name="value" type="password" autoComplete="new-password" required /></div><Feedback message={fetcher.data?.ok === false ? fetcher.data.message : undefined} error />{fetcher.state !== "idle" ? <Pending /> : null}<Button type="submit" disabled={fetcher.state !== "idle"}>Save version</Button></fetcher.Form>
    </Dialog>
    <Dialog open={historyKey !== null} onOpenChange={open => { if (!open) { readSequence.current++; setHistoryKey(null); setRevealed(null); setReading(false) } }} title={historyKey || "Secret versions"} description="Reading a value requires secret:Read and is audited. Revealed values are hidden again after 30 seconds.">
      <Feedback message={historyError} error /><div className="space-y-3">{versions.map(version => <div className="flex items-center justify-between gap-3 rounded-lg border border-border p-3" key={version.version}><span>Version {version.version}{version.destroyed ? " (destroyed)" : ""}</span><Button variant="secondary" onClick={() => reveal(version.version)} disabled={version.destroyed || reading}><Eye />Reveal</Button></div>)}</div>
      {revealed !== null && <div className="mt-5"><Label htmlFor="revealed-value">Revealed value</Label><Input id="revealed-value" value={revealed} readOnly autoComplete="off" /><Button className="mt-3" variant="secondary" onClick={() => setRevealed(null)}><EyeOff />Hide value</Button></div>}
    </Dialog>
  </>
}
