/**
 * matchesQuery is the dashboard's one search behaviour: a case-insensitive
 * substring match over the fields a row actually shows. An empty or
 * whitespace-only query matches everything, so a cleared search box is the
 * unfiltered list rather than an empty one.
 */
export function matchesQuery(query: string, ...haystacks: (string | undefined)[]): boolean {
  const q = query.trim().toLowerCase()
  if (q === '') return true
  return haystacks.some((h) => h !== undefined && h.toLowerCase().includes(q))
}
