// The lazily imported xterm stylesheet: TS cannot resolve the subpath through
// the package's exports map, so it needs an ambient declaration. Vite bundles
// the file into the xterm async chunk, which is the point of the dynamic
// import.
declare module '@xterm/xterm/css/xterm.css'
