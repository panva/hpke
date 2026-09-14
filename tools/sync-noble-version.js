import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// commit-and-tag-version invokes this after its prerelease build and root version bump. Syncing
// dependency ranges before comparing packed contents includes dependency updates while keeping
// source-only changes from forcing a noble package release.
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const defaultNobleDirectory = join(root, 'examples/noble-suite')
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const registry = 'https://registry.npmjs.org/'

function manifest(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

export function noblePackageDrift({
  baseline,
  directory = defaultNobleDirectory,
  npmCommand = npm,
  stderr = 'inherit',
} = {}) {
  const noble = manifest(join(directory, 'package.json'))
  const specifier = baseline ?? `${noble.name}@${noble.version}`
  const staging = mkdtempSync(join(tmpdir(), 'hpke-noble-diff-'))
  let output
  try {
    try {
      output = execFileSync(
        npmCommand,
        [
          'diff',
          `--diff=${specifier}`,
          `--diff=file:${resolve(directory)}`,
          '--diff-name-only',
          '--color=false',
          '--loglevel=error',
          '--min-release-age=0',
          `--registry=${registry}`,
          '--cache',
          join(staging, 'npm-cache'),
        ],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', stderr] },
      )
    } catch (cause) {
      throw new Error(`failed to compare ${directory} with ${specifier}`, { cause })
    }
  } finally {
    rmSync(staging, { recursive: true, force: true })
  }
  const changes = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  return { changed: changes.length !== 0, changes, name: noble.name, version: noble.version }
}

export function syncNobleVersion({
  baseline,
  directory = defaultNobleDirectory,
  log = console.log,
  npmCommand = npm,
  rootManifest = join(root, 'package.json'),
  stderr = 'inherit',
} = {}) {
  const hpke = manifest(rootManifest)
  const nobleManifest = join(directory, 'package.json')
  const original = readFileSync(nobleManifest, 'utf8')
  const noble = JSON.parse(original)
  let dependenciesChanged = false
  for (const [name, currentRange] of Object.entries(noble.dependencies ?? {})) {
    if (!name.startsWith('@noble/')) continue
    const range = hpke.devDependencies?.[name]
    if (!range) {
      throw new Error(`missing root devDependency for ${name}`)
    }
    if (range !== currentRange) {
      noble.dependencies[name] = range
      dependenciesChanged = true
    }
  }

  try {
    if (dependenciesChanged) {
      writeFileSync(nobleManifest, `${JSON.stringify(noble, null, 2)}\n`)
    }
    const drift = noblePackageDrift({ baseline, directory, npmCommand, stderr })

    if (!drift.changed) {
      log(`${noble.name}@${noble.version} matches its published artifact; keeping its version`)
      return { ...drift, previousVersion: noble.version, targetVersion: noble.version }
    }
    if (noble.version === hpke.version) {
      throw new Error(
        `${noble.name}@${noble.version} has unpublished package drift but already uses the target version`,
      )
    }

    const previousVersion = noble.version
    noble.version = hpke.version
    writeFileSync(nobleManifest, `${JSON.stringify(noble, null, 2)}\n`)
    log(
      `${noble.name} package drift detected in ${drift.changes.join(', ')}; ` +
        `bumped ${previousVersion} to ${noble.version}`,
    )
    return { ...drift, previousVersion, targetVersion: noble.version }
  } catch (cause) {
    if (dependenciesChanged) {
      writeFileSync(nobleManifest, original)
    }
    throw cause
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  syncNobleVersion()
}
