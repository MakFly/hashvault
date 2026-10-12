import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const variants = cva("inline-flex min-h-11 items-center justify-center gap-2 rounded-lg px-4 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4", {
  variants: { variant: { default: "bg-primary text-primary-foreground hover:bg-primary/90", secondary: "border border-border bg-background text-foreground hover:bg-muted", ghost: "text-foreground hover:bg-muted", destructive: "bg-destructive text-white hover:bg-destructive/90" } },
  defaultVariants: { variant: "default" },
})

export function Button({ className, variant, asChild = false, ...props }: React.ComponentProps<"button"> & VariantProps<typeof variants> & { asChild?: boolean }) {
  const Component = asChild ? Slot : "button"
  return <Component className={cn(variants({ variant }), className)} {...props} />
}
