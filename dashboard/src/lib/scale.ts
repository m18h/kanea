import type { Service } from '@/lib/api'

/**
 * scaleBounds is what a manual scale may reach, and it mirrors `handleScale`
 * in `internal/api` rather than inventing a rule of its own.
 *
 * The daemon **refuses** a count outside a declared policy's range with a 409
 * rather than clamping it, on the grounds that the autoscaler would undo it
 * within seconds and silently doing something other than what was asked is
 * worse than saying no. So a control built on this stops where the daemon
 * would refuse: offering a click that is guaranteed to fail is the same
 * mistake one layer up.
 *
 * The condition is copied exactly, including the two halves that look
 * redundant and are not: a policy bounds a manual scale only when it declares
 * a `max` **and** at least one metric, because a policy with no metric can
 * never fire and would otherwise pin a service to a range nothing enforces.
 * If that condition changes on the daemon it changes here, and
 * `ServiceActions.test.tsx` fails until it does.
 *
 * The floor is at least one. Zero is a stop, and Stop owns it.
 */
export function scaleBounds(desired: Service): {
  min: number
  max: number
  hint: string | undefined
} {
  const policy = desired.Scaling
  const bounded = policy != null && policy.max > 0 && (policy.metrics?.length ?? 0) > 0
  if (!policy || !bounded) {
    return { min: 1, max: Number.POSITIVE_INFINITY, hint: undefined }
  }
  return {
    min: Math.max(policy.min, 1),
    max: policy.max,
    hint:
      `Autoscales between ${policy.min} and ${policy.max}: a manual count outside that ` +
      `is refused, and one inside it stands until the next autoscale decision.`,
  }
}
