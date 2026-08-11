// Runs @arethetypeswrong/cli over the packed tarball and fails on anything except the one known,
// accepted class of report:
//
//   - cjs-resolves-to-esm: by design. There is no CJS build, and adding a "require" condition
//     pointing at the ESM file would assert a compatibility that does not exist.
//
// This package keeps top-level "main" and "types", so the legacy node10 resolver finds the module
// and its declarations. That is checked rather than ignored, so losing it fails here.
//
// Anything else - an untyped resolution, a masquerading module, or a missing entry point - is a
// real packaging defect and fails the build.
import { spawnSync } from 'node:child_process'
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const IGNORED_PROBLEM_KINDS = new Set(['CJSResolvesToESM'])
const packageDir = process.argv[2] ?? '.'

// The report includes a full module resolution trace per entry point and can run past the pipe
// buffer spawnSync captures, so route it through a file. attw also exits non-zero whenever it finds
// any problem, including the one accepted above, so the exit code is not the signal - the JSON is.
const dir = mkdtempSync(join(tmpdir(), 'hpke-attw-'))
const out = join(dir, 'report.json')

// Resolve from node_modules instead of fetching at runtime. The pinned devDependency and lockfile
// determine the executable version and integrity hash.
const require = createRequire(import.meta.url)
const manifest = require.resolve('@arethetypeswrong/cli/package.json')
const { bin } = require(manifest)
const attw = join(manifest, '..', typeof bin === 'string' ? bin : bin.attw)

let stdout
const fd = openSync(out, 'w')
try {
  const { error, stderr } = spawnSync(
    process.execPath,
    [attw, '--pack', packageDir, '--format', 'json'],
    { encoding: 'utf8', stdio: ['ignore', fd, 'pipe'] },
  )
  closeSync(fd)
  if (error) {
    console.error(error.message || stderr)
    process.exit(1)
  }
  stdout = readFileSync(out, 'utf8')
} finally {
  rmSync(dir, { recursive: true, force: true })
}

if (!stdout) {
  console.error('no output from @arethetypeswrong/cli')
  process.exit(1)
}

const report = JSON.parse(stdout)

if (report.analysis?.problems === undefined && report.problems === undefined) {
  console.error('unexpected @arethetypeswrong output shape:')
  console.error(stdout.slice(0, 2000))
  process.exit(1)
}

const problems = report.analysis?.problems ?? report.problems ?? []
const unexpected = problems.filter((problem) => !IGNORED_PROBLEM_KINDS.has(problem.kind))
const ignored = problems.length - unexpected.length

if (unexpected.length) {
  console.error(`@arethetypeswrong reported ${unexpected.length} unexpected problem(s):`)
  for (const problem of unexpected) {
    console.error(
      `  ${problem.kind} (${problem.resolutionKind ?? 'n/a'}) ${problem.entrypoint ?? ''}`,
    )
  }
  process.exit(1)
}

console.log(`OK - no unexpected packaging problems (${ignored} known/accepted ignored)`)
