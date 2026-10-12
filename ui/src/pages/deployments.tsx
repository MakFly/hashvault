import { useEffect, useState } from "react"
import { Form, useFetcher, useLoaderData, useOutletContext, type ActionFunctionArgs, type LoaderFunctionArgs } from "react-router"
import { Check, Download, Plus } from "lucide-react"
import { ApiError, pathPart, request, saveDescriptor, type Manifest, type Preparation, type Publication, type Target } from "@/api/client"
import { Empty, Feedback, PageHeader, Pending, readableDate, Scope, scopeFromURL } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Dialog } from "@/components/ui/dialog"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export async function deploymentsLoader({ request: req }: LoaderFunctionArgs) {
  const { env, app } = scopeFromURL(req.url)
  const target = new URL(req.url).searchParams.get("target") || ""
  let targets: string[] = [], preparations: Preparation[] = [], publication: Publication | null = null, error = ""
  let targetMatchesEnvironment = false
  try { targets = (await request<{ targets: string[] }>("/v1/targets")).targets || [] } catch (failure) { error = failure instanceof Error ? failure.message : "Could not load targets." }
  if (app && target) {
    try {
      const registered = await request<Target>(`/v1/targets/${pathPart(target)}`)
      if (registered.env !== env) throw new Error(`This target deploys to ${registered.env}. Select that environment before preparing secrets.`)
      targetMatchesEnvironment = true
      const [snapshots, active] = await Promise.all([request<{ preparations: Preparation[] }>(`/v1/preparations?${new URLSearchParams({ target, app })}`), request<{ publication: Publication | null }>(`/v1/publications/${pathPart(target)}/${pathPart(app)}`)])
      preparations = snapshots.preparations; publication = active.publication
    } catch (failure) { if (!(failure instanceof ApiError && failure.status === 404)) error = failure instanceof Error ? failure.message : "Could not load preparations." }
  }
  return { env, app, target, targets, preparations, publication, error, targetMatchesEnvironment }
}

export async function deploymentAction({ request: req }: ActionFunctionArgs) {
  const form = await req.formData()
  try {
    if (form.get("intent") === "confirm") {
      await request(`/v1/preparations/${pathPart(String(form.get("id")))}/confirm`, { method: "POST", body: JSON.stringify({ release: String(form.get("release")), previous: String(form.get("previous") || "") }) })
      return { ok: true, message: "Release recorded with its pinned secret versions." }
    }
    const manifest = JSON.parse(String(form.get("manifest"))) as Manifest
    if (manifest?.app !== form.get("app")) throw new Error("The manifest application must match the selected application.")
    const registered = await request<Target>(`/v1/targets/${pathPart(String(form.get("target")))}`)
    if (registered.env !== form.get("env")) throw new Error(`This target deploys to ${registered.env}. Select that environment first.`)
    await request<Preparation>("/v1/preparations", { method: "POST", body: JSON.stringify({ target: String(form.get("target")), manifest }) })
    return { ok: true, message: "Secrets prepared. No running service was changed. Use the descriptor in your deployment." }
  } catch (error) { return { ok: false, message: error instanceof Error ? error.message : "The preparation could not be completed." } }
}

export function DeploymentsPage() {
  const data = useLoaderData<typeof deploymentsLoader>()
  const { available } = useOutletContext<{ available: boolean }>()
  const fetcher = useFetcher<typeof deploymentAction>()
  const [preparing, setPreparing] = useState(false)
  const [confirming, setConfirming] = useState<Preparation | null>(null)
  const [manifest, setManifest] = useState("")
  useEffect(() => { if (fetcher.state === "idle" && fetcher.data?.ok) { setPreparing(false); setConfirming(null) } }, [fetcher.state, fetcher.data])
  function startPreparation() {
    setManifest(JSON.stringify({ version: "hv-manifest-1", app: data.app, items: { DATABASE_URL: { expose: "env", services: ["api"], uid: "1000", gid: "1000", mode: "0400" } } }, null, 2)); setPreparing(true)
  }
  return <>
    <PageHeader title="Deployments" description="Prepare secrets before deploying. Each descriptor keeps the exact versions and mounts a release needs."><Button disabled={!available || !data.app || !data.target || !data.targetMatchesEnvironment} onClick={startPreparation}><Plus />Prepare secrets</Button></PageHeader>
    <Scope /><Form method="get" className="mb-6 flex flex-wrap items-end gap-3"><input type="hidden" name="env" value={data.env} /><input type="hidden" name="app" value={data.app} /><div className="min-w-0 flex-1"><Label htmlFor="deployment-target">Deployment target</Label><Input id="deployment-target" list="target-names" name="target" required defaultValue={data.target} placeholder="Select a registered target" /><datalist id="target-names">{data.targets.map(target => <option value={target} key={target} />)}</datalist></div><Button type="submit" variant="secondary">Open target</Button></Form>
    <Feedback message={data.error} error /><Feedback message={fetcher.state === "idle" ? fetcher.data?.message : undefined} error={fetcher.data?.ok === false} />
    {data.publication && <div className="surface mb-6 p-5"><span className="status ready">Last confirmed release</span><h2 className="mt-3 text-lg font-medium">{data.publication.release || "Published directly"}</h2><p className="record-meta">{readableDate(data.publication.at)} by {data.publication.by}</p><p className="record-meta">A confirmation records the deployer’s completed health checks.</p></div>}
    <div className="surface">{data.preparations.length ? data.preparations.map(preparation => <div className="border-b border-border last:border-b-0" key={preparation.id}><div className="record"><div className="record-main"><h2 className="record-title">{preparation.app} <span className="font-normal text-muted-foreground">on {preparation.target}</span></h2><p className="record-meta">{readableDate(preparation.at)} by {preparation.by}</p><p className="record-meta">{Object.entries(preparation.items).map(([key, item]) => `${key} v${item.version}`).join(", ")}</p></div><div className="flex flex-wrap gap-2"><Button variant="secondary" onClick={() => saveDescriptor(preparation)}><Download />Descriptor</Button><Button variant="ghost" onClick={() => setConfirming(preparation)} disabled={!available}><Check />Record release</Button></div></div><details className="px-6 pb-5"><summary className="cursor-pointer text-sm text-primary">Inspect references</summary><pre className="mt-3 rounded-lg bg-muted p-4">{JSON.stringify(preparation, null, 2)}</pre></details></div>) : <Empty title={data.app && data.target ? "No preparations yet" : "Choose an application and a target"}>A preparation installs secrets without restarting your services. Your deployment tool uses the resulting references.</Empty>}</div>
    <Dialog open={preparing} onOpenChange={setPreparing} title="Prepare secrets" description="Use your application’s hashvault.json. Service names and file owners must match the deployment. The example below is editable."><fetcher.Form method="post" className="form-grid"><input type="hidden" name="target" value={data.target} /><input type="hidden" name="env" value={data.env} /><input type="hidden" name="app" value={data.app} /><div><Label htmlFor="deployment-manifest">Application manifest</Label><Textarea id="deployment-manifest" name="manifest" required rows={12} className="font-mono text-sm" value={manifest} onChange={event => setManifest(event.target.value)} /></div><Feedback message={fetcher.data?.ok === false ? fetcher.data.message : undefined} error />{fetcher.state !== "idle" && <Pending />}<Button type="submit" disabled={fetcher.state !== "idle" || !available || !data.targetMatchesEnvironment}>Prepare on {data.target}</Button></fetcher.Form></Dialog>
    <Dialog open={!!confirming} onOpenChange={open => { if (!open) setConfirming(null) }} title="Record a deployed release" description="Deploy with this preparation first and verify the application’s health. Recording the release does not deploy or restart anything."><fetcher.Form method="post" className="form-grid"><input type="hidden" name="intent" value="confirm" /><input type="hidden" name="id" value={confirming?.id || ""} /><input type="hidden" name="previous" value={data.publication?.preparation_id || ""} /><div><Label htmlFor="release-name">Release identity</Label><Input id="release-name" name="release" required maxLength={128} placeholder="Commit SHA or release tag" /></div><label className="flex min-h-11 items-start gap-3 text-sm leading-relaxed"><input type="checkbox" required className="mt-1 size-5 shrink-0" />The release uses this preparation and its health checks succeeded.</label><Feedback message={fetcher.data?.ok === false ? fetcher.data.message : undefined} error /><Button type="submit" disabled={fetcher.state !== "idle"}>Record release</Button></fetcher.Form></Dialog>
  </>
}
