import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** cn merges Tailwind classes, letting a caller override a component default. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
