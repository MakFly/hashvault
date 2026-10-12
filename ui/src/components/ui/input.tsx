import type { ComponentProps } from "react"
import { cn } from "@/lib/utils"

export function Input({ className, ...props }: ComponentProps<"input">) {
  return <input className={cn("min-h-11 w-full rounded-lg border border-input bg-background px-3 py-2 text-base text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50", className)} {...props} />
}
export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea className={cn("min-h-32 w-full rounded-lg border border-input bg-background p-3 text-base text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring", className)} {...props} />
}
