import { useEffect, useState } from "react"
import { useFetcher, useLoaderData, useOutletContext, type ActionFunctionArgs } from "react-router"
import { Plus, Server } from "lucide-react"
import { pathPart, request, type Target } from "@/api/client"
import { Empty, Feedback, PageHeader } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Dialog } from "@/components/ui/dialog"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export async function targetsLoader() {
  try { const { targets } = await request<{ targets: string[] }>("/v1/targets"); const records = await Promise.all((targets || []).map(name => request<Target>(`/v1/targets/${pathPart(name)}`))); return { targets: records, error: "" } }
  catch (error) { return { targets: [] as Target[], error: error instanceof Error ? error.message : "Could not load targets." } }
}
export async function targetAction({ request: req }: ActionFunctionArgs) {
  const form = await req.formData()
  try {
    const name = String(form.get("name"))
    await request(`/v1/targets/${pathPart(name)}`, { method: "PUT", body: JSON.stringify({ name, kind: String(form.get("kind")), env: String(form.get("env")), config: JSON.parse(String(form.get("config"))) }) })
    return { ok: true, message: `${name} registered.` }
  } catch (error) { return { ok: false, message: error instanceof Error ? error.message : "Could not register the target." } }
}

export function TargetsPage() {
  const { targets, error } = useLoaderData<typeof targetsLoader>()
  const { available } = useOutletContext<{ available: boolean }>()
  const fetcher = useFetcher<typeof targetAction>()
  const [editor, setEditor] = useState<Target | "new" | null>(null)
  const [kind, setKind] = useState("swarm")
  const [config, setConfig] = useState("")
  useEffect(() => { if (fetcher.state === "idle" && fetcher.data?.ok) setEditor(null) }, [fetcher.state, fetcher.data])
  function edit(target: Target | "new") { setEditor(target); setKind(target === "new" ? "swarm" : target.kind); setConfig(JSON.stringify(target === "new" ? { docker: "unix:///var/run/docker.sock", stack: "acme-api" } : target.config, null, 2)) }
  return <>
    <PageHeader title="Targets" description="Register where secrets should be prepared. Each target belongs to one environment."><Button onClick={() => edit("new")} disabled={!available}><Plus />Register target</Button></PageHeader>
    <Feedback message={error} error /><Feedback message={fetcher.state === "idle" ? fetcher.data?.message : undefined} error={fetcher.data?.ok === false} />
    <div className="surface">{targets.length ? targets.map(target => <div className="record" key={target.name}><div className="record-main"><h2 className="record-title flex items-center gap-3"><Server className="size-4 text-primary" aria-hidden="true" />{target.name}</h2><p className="record-meta">{target.kind} / {target.env}</p></div><Button variant="secondary" onClick={() => edit(target)} disabled={!available}>Configuration</Button></div>) : <Empty title="No registered targets">Register your Swarm manager or an enrolled Docker/SSH agent to prepare the first deployment.</Empty>}</div>
    <Dialog open={editor !== null} onOpenChange={open => { if (!open) setEditor(null) }} title={editor === "new" ? "Register target" : "Target configuration"} description="Swarm uses the manager’s local Docker socket. Docker and SSH targets use an enrolled agent and a restricted transport."><fetcher.Form method="post" className="form-grid"><div><Label htmlFor="target-name">Name</Label><Input id="target-name" name="name" required pattern="[a-z0-9][a-z0-9-]{0,62}" defaultValue={editor && editor !== "new" ? editor.name : ""} readOnly={editor !== "new"} /></div><div><Label htmlFor="target-kind">Runtime</Label><select id="target-kind" name="kind" className="min-h-11 w-full rounded-lg border border-input bg-background px-3" value={kind} onChange={event => { setKind(event.target.value); setConfig(JSON.stringify(event.target.value === "swarm" ? { docker: "unix:///var/run/docker.sock", stack: "acme-api" } : { agent: "web-01", recipient: "", transport: { type: "ssh", host: "", user: "hashvault", key_file: "", known_hosts_file: "" } }, null, 2)) }}><option value="swarm">Docker Swarm</option><option value="docker">Docker / Compose</option><option value="ssh">SSH deployment</option></select></div><div><Label htmlFor="target-env">Environment</Label><Input id="target-env" name="env" required defaultValue={editor && editor !== "new" ? editor.env : "prod"} /></div><div><Label htmlFor="target-config">Runtime configuration</Label><Textarea id="target-config" name="config" rows={9} className="font-mono text-sm" value={config} onChange={event => setConfig(event.target.value)} required /></div><Feedback message={fetcher.data?.ok === false ? fetcher.data.message : undefined} error /><Button type="submit" disabled={fetcher.state !== "idle"}>Save target</Button></fetcher.Form></Dialog>
  </>
}
