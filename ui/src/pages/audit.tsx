import { useFetcher } from "react-router"
import { ShieldCheck } from "lucide-react"
import { request } from "@/api/client"
import { Feedback, PageHeader, Pending } from "@/components/shared"
import { Button } from "@/components/ui/button"

export async function auditAction() {
  try { const result = await request<Record<string, unknown>>("/v1/audit/verify"); return { ok: true, result, error: "" } }
  catch (failure) { return { ok: false, result: null, error: failure instanceof Error ? failure.message : "Could not verify the audit log." } }
}
export function AuditPage() {
  const fetcher = useFetcher<typeof auditAction>()
  return <>
    <PageHeader title="Audit integrity" description="Reads, writes, access changes and deployment preparations are recorded before execution. Verify the log’s hash chain and signed checkpoints." />
    <div className="surface max-w-3xl p-7"><ShieldCheck className="mb-4 size-7 text-primary" aria-hidden="true" /><h2 className="text-xl font-medium">Verify the vault’s audit log</h2><p className="mt-3 max-w-xl text-sm leading-relaxed text-muted-foreground">This checks the locally recorded chain. Off-host anchors provide separate evidence against a host rewriting its own history.</p><fetcher.Form method="post" className="mt-6"><Button disabled={fetcher.state !== "idle"}>Verify integrity</Button></fetcher.Form><div className="mt-5"><Feedback message={fetcher.data?.error} error />{fetcher.state !== "idle" && <Pending />}{fetcher.data?.result && <pre className="rounded-lg bg-muted p-4">{JSON.stringify(fetcher.data.result, null, 2)}</pre>}</div></div>
  </>
}
