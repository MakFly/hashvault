import * as DialogPrimitive from "@radix-ui/react-dialog"
import { X } from "lucide-react"
import type { ReactNode } from "react"

export function Dialog({ open, onOpenChange, title, description, children }: { open: boolean; onOpenChange: (open: boolean) => void; title: string; description: string; children: ReactNode }) {
  return <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-slate-950/35" />
      <DialogPrimitive.Content className="fixed left-1/2 top-1/2 z-50 max-h-[calc(100dvh_-_2rem)] w-[calc(100%_-_2rem)] max-w-xl -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl border border-border bg-card p-6 shadow-xl">
        <DialogPrimitive.Title className="pr-10 text-xl font-semibold">{title}</DialogPrimitive.Title>
        <DialogPrimitive.Description className="mt-2 text-sm leading-relaxed text-muted-foreground">{description}</DialogPrimitive.Description>
        <DialogPrimitive.Close className="absolute right-3 top-3 flex size-11 items-center justify-center rounded-lg hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring" aria-label="Close dialog"><X size={18} /></DialogPrimitive.Close>
        <div className="mt-6">{children}</div>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  </DialogPrimitive.Root>
}
