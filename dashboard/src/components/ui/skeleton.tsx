import { cn } from '@/lib/utils'

/**
 * Skeleton is the loading placeholder primitive: a pulsing block sized by the
 * caller to match what will replace it, so the page keeps its shape while
 * data arrives instead of popping taller when it does.
 */
export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div aria-hidden className={cn('animate-pulse rounded-md bg-muted', className)} {...props} />
}
