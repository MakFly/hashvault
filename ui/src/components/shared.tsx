import type { ReactNode } from "react"
import { Form, useSearchParams } from "react-router"
import { Archive, LoaderCircle } from "lucide-react"
import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { Label } from "./ui/label"

export function PageHeader({ title, description, children }: { title: string; description: string; children?: ReactNode }) {
  return <div className="section-header"><div><h1 className="page-title">{title}</h1><p className="page-intro">{description}</p></div>{children}</div>
}
export function Feedback({ message, error = false }: { message?: string; error?: boolean }) {
  return message ? <div role={error ? "alert" : "status"} className={`feedback${error ? " error" : ""}`}>{message}</div> : null
}
export function Empty({ title, children }: { title: string; children: ReactNode }) {
  return <div className="empty"><Archive size={26} aria-hidden="true" /><h2>{title}</h2><p className="mx-auto mt-2 max-w-lg text-sm leading-relaxed">{children}</p></div>
}
export function Pending() { return <div className="flex items-center gap-2 text-sm text-muted-foreground" role="status"><LoaderCircle className="size-4 animate-spin" aria-hidden="true" />Working…</div> }
export function Scope() {
  const [query] = useSearchParams()
  return <Form method="get" className="scope-form surface">
    {query.get("target") && <input type="hidden" name="target" value={query.get("target") || ""} />}
    <div><Label htmlFor="scope-env">Environment</Label><Input id="scope-env" name="env" required pattern="[a-z][a-z0-9-]{0,31}" defaultValue={query.get("env") || "prod"} /></div>
    <div><Label htmlFor="scope-app">Application</Label><Input id="scope-app" name="app" required pattern="[a-z0-9][a-z0-9-]{0,62}" defaultValue={query.get("app") || ""} placeholder="Application name" /></div>
    <Button variant="secondary" type="submit">Open application</Button>
  </Form>
}
export function scopeFromURL(url: string) {
  const query = new URL(url).searchParams
  return { env: query.get("env") || "prod", app: query.get("app") || "" }
}
export function readableDate(value: string) { return new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) }
