import { useEffect } from 'react'

/** useDocumentTitle keeps the browser tab in step with the page. */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title
  }, [title])
}
