export type ReadmeSupportRuntime = 'node' | 'deno' | 'bun' | 'browser' | 'workerd'
export type ReadmeSupportComponent = 'kem' | 'kdf' | 'aead'

export type ReadmeSupportTestResult = {
  status: string
  implementation?: string
  component: ReadmeSupportComponent
  algorithm?: string
  name?: string
}

export type ReadmeSupportMismatch = {
  component: ReadmeSupportComponent
  algorithm?: string
  name: string
  runtime: ReadmeSupportRuntime
}

export function findReadmeSupportMismatches(options: {
  results: { tests: ReadmeSupportTestResult[] }
  readme: string
  runtime: ReadmeSupportRuntime
}): ReadmeSupportMismatch[]

export function formatReadmeSupportMismatch(mismatch: ReadmeSupportMismatch): string
