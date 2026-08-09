import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        ok: 'border-transparent bg-status-ok/15 text-status-ok',
        warn: 'border-transparent bg-status-warn/15 text-status-warn',
        error: 'border-transparent bg-status-error/15 text-status-error',
        info: 'border-transparent bg-status-info/15 text-status-info',
        // The amber fill pill — "building", an autoscale policy chip.
        accent: 'border-transparent bg-primary/15 text-primary',
        // The amber outline pill — "staged", the build-slot chip.
        'outline-warn': 'border-status-warn/50 bg-transparent text-status-warn',
        muted: 'border-border text-muted-foreground',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

export type BadgeProps = React.HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants>

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
