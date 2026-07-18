/// <reference types="vite/client" />

// TypeScript 7 validates even side-effect imports; Vite handles CSS at build
// time, so declare it for the typechecker.
declare module '*.css'
