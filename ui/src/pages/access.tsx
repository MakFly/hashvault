import { useEffect, useState } from "react"
import { useFetcher, useLoaderData, useOutletContext, type ActionFunctionArgs } from "react-router"
import { FileKey, Fingerprint, Plus } from "lucide-react"
import { pathPart, request, type Principal } from "@/api/client"
import { Empty, Feedback, PageHeader } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Dialog } from "@/components/ui/dialog"
import { Input, Textarea } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export async function accessLoader() {
  let principals: Principal[] = [], policies: string[] = [], error = ""
  try { const list = await request<{ principals: string[] }>("/v1/principals"); principals = await Promise.all((list.principals || []).map(name => request<Principal>(`/v1/principals/${name.split("/").map(pathPart).join("/")}`))) } catch (failure) { error = failure instanceof Error ? failure.message : "Could not load principals." }
  try { policies = (await request<{ policies: string[] }>("/v1/policies")).policies || [] } catch (failure) { error = failure instanceof Error ? failure.message : "Could not load policies." }
  return { principals, policies, error }
}

export async function accessAction({ request: req }: ActionFunctionArgs) {
  const form = await req.formData()
  const intent = String(form.get("intent")), name = String(form.get("name"))
  try {
    if (intent === "principal") {
      await request("/v1/principals", { method: "POST", body: JSON.stringify({ name, ssh_key: String(form.get("key")) }) })
      return { ok: true, message: "Principal enrolled. Attach a policy before it can access resources." }
    }
    if (intent === "attach") {
      await request(`/v1/principals/${name.split("/").map(pathPart).join("/")}/attach`, { method: "POST", body: JSON.stringify({ policy: String(form.get("policy")), boundary: form.get("boundary") === "on", detach: form.get("detach") === "on" }) })
      return { ok: true, message: "Principal policy updated." }
    }
    if (intent === "disable") {
      await request(`/v1/principals/${name.split("/").map(pathPart).join("/")}/disable`, { method: "POST" })
      return { ok: true, message: "Principal disabled. New requests are refused." }
    }
    await request(`/v1/policies/${pathPart(name)}`, { method: "PUT", body: JSON.stringify(JSON.parse(String(form.get("document")))) })
    return { ok: true, message: "Policy saved." }
  } catch (error) { return { ok: false, message: error instanceof Error ? error.message : "Could not update access." } }
}

type Editor = { kind: "principal" } | { kind: "policy"; name: string } | { kind: "attach"; principal: Principal } | { kind: "disable"; principal: Principal }

export function AccessPage() {
  const { principals, policies, error } = useLoaderData<typeof accessLoader>()
  const { available } = useOutletContext<{ available: boolean }>()
  const fetcher = useFetcher<typeof accessAction>()
  const [editor, setEditor] = useState<Editor | null>(null)
  const [document, setDocument] = useState("")
  const [editorError, setEditorError] = useState("")
  useEffect(() => { if (fetcher.state === "idle" && fetcher.data?.ok) setEditor(null) }, [fetcher.state, fetcher.data])
  async function editPolicy(name: string) {
    setEditorError(""); setDocument(""); setEditor({ kind: "policy", name })
    if (!name) { setDocument(JSON.stringify({ Version: "hv-1", Statement: [{ Effect: "Allow", Action: "secret:List", Resource: "hv:prod:secret/acme-api" }] }, null, 2)); return }
    try { const policy = await request<{ document: unknown }>(`/v1/policies/${pathPart(name)}`); setDocument(JSON.stringify(policy.document, null, 2)) } catch (failure) { setEditorError(failure instanceof Error ? failure.message : "Could not load policy.") }
  }
  return <>
    <PageHeader title="Access" description="Enroll identities and grant explicit permissions. Deployment machines can prepare secrets without reading their values."><Button onClick={() => { setEditorError(""); setEditor({ kind: "principal" }) }} disabled={!available}><Plus />Enroll principal</Button></PageHeader>
    <Feedback message={error} error /><Feedback message={fetcher.state === "idle" ? fetcher.data?.message : undefined} error={fetcher.data?.ok === false} />
    <h2 className="mb-3 text-lg font-medium">Principals</h2><div className="surface mb-8">{principals.length ? principals.map(principal => <div className="record" key={principal.name}><div className="record-main"><h3 className="record-title flex items-center gap-3"><Fingerprint className="size-4 text-primary" aria-hidden="true" />{principal.name}</h3><p className="record-meta">{principal.disabled ? "Disabled" : "Active"}. Policies: {principal.policies?.join(", ") || "none"}</p>{principal.boundary?.length ? <p className="record-meta">Boundary: {principal.boundary.join(", ")}</p> : null}</div><div className="flex flex-wrap gap-2"><Button variant="secondary" onClick={() => { setEditorError(""); setEditor({ kind: "attach", principal }) }} disabled={!available || principal.disabled}>Policies</Button><Button variant="ghost" onClick={() => { setEditorError(""); setEditor({ kind: "disable", principal }) }} disabled={!available || principal.disabled}>Disable</Button></div></div>) : <Empty title="No principals to display">Your account needs principal:Read to inspect enrolled identities.</Empty>}</div>
    <div className="section-header"><h2 className="text-lg font-medium">Policies</h2><Button variant="secondary" onClick={() => editPolicy("")} disabled={!available}><Plus />Add policy</Button></div><div className="surface">{policies.length ? policies.map(name => <div className="record" key={name}><div className="record-main"><h3 className="record-title flex items-center gap-3"><FileKey className="size-4 text-primary" aria-hidden="true" />{name}</h3><p className="record-meta">Explicit deny takes precedence.</p></div><Button variant="secondary" onClick={() => editPolicy(name)} disabled={!available}>Open policy</Button></div>) : <Empty title="No policies to display">Create a policy with permissions scoped to an environment and application.</Empty>}</div>
    <Dialog open={!!editor} onOpenChange={open => { if (!open) { setEditor(null); setDocument("") } }} title={editor?.kind === "principal" ? "Enroll principal" : editor?.kind === "policy" ? "Policy document" : editor?.kind === "disable" ? "Disable principal" : "Manage principal policies"} description={editor?.kind === "disable" ? "This account will be refused on subsequent requests. Its stored secrets and existing deployments are retained." : "Changes are validated and audited by the vault. Private keys never belong in this form."}>
      <Feedback message={editorError} error /><fetcher.Form method="post" className="form-grid"><input type="hidden" name="intent" value={editor?.kind || ""} />
        {editor?.kind === "principal" && <><div><Label htmlFor="principal-name">Principal name</Label><Input id="principal-name" name="name" required placeholder="machine/deployer or human/operator" /></div><div><Label htmlFor="principal-key">SSH public key</Label><Textarea id="principal-key" name="key" required rows={3} placeholder="ssh-ed25519 … or sk-ssh-ed25519 …" /></div></>}
        {editor?.kind === "policy" && <><div><Label htmlFor="policy-name">Policy name</Label><Input id="policy-name" name="name" required pattern="[a-z0-9][a-z0-9\-]{0,62}" defaultValue={editor.name} readOnly={!!editor.name} /></div><div><Label htmlFor="policy-document">IAM document</Label><Textarea id="policy-document" name="document" required rows={13} className="font-mono text-sm" value={document} onChange={event => setDocument(event.target.value)} /></div></>}
        {editor?.kind === "attach" && <><input type="hidden" name="name" value={editor.principal.name} /><p className="text-sm">{editor.principal.name}</p><div><Label htmlFor="attached-policy">Policy</Label><select id="attached-policy" name="policy" required className="min-h-11 w-full rounded-lg border border-input bg-background px-3"><option value="">Select a policy</option>{policies.map(name => <option key={name} value={name}>{name}</option>)}</select></div><label className="flex min-h-11 items-center gap-3 text-sm"><input className="size-5" type="checkbox" name="boundary" />Apply as a permission boundary</label><label className="flex min-h-11 items-center gap-3 text-sm"><input className="size-5" type="checkbox" name="detach" />Remove this policy instead of attaching it</label></>}
        {editor?.kind === "disable" && <><input type="hidden" name="name" value={editor.principal.name} /><p className="font-medium">{editor.principal.name}</p></>}
        <Feedback message={fetcher.data?.ok === false ? fetcher.data.message : undefined} error /><Button type="submit" variant={editor?.kind === "disable" ? "destructive" : "default"} disabled={fetcher.state !== "idle" || !!editorError}>{editor?.kind === "disable" ? "Disable principal" : "Save changes"}</Button>
      </fetcher.Form>
    </Dialog>
  </>
}
