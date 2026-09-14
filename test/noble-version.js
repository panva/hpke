import { strict as assert } from 'node:assert'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import it, * as test from 'node:test'

import { syncNobleVersion } from '../tools/sync-noble-version.js'

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`)
}

function fixture(t, rootVersion = '2.0.0', nobleVersion = '1.0.0') {
  const temporary = mkdtempSync(join(tmpdir(), 'hpke-noble-version-test-'))
  t.after(() => rmSync(temporary, { recursive: true, force: true }))

  const baseline = join(temporary, 'baseline')
  const directory = join(temporary, 'current')
  mkdirSync(baseline)
  mkdirSync(directory)

  const noble = {
    name: '@example/hpke-noble',
    version: nobleVersion,
    type: 'module',
    main: 'index.js',
    types: 'index.d.ts',
    files: ['index.js', 'index.d.ts'],
    dependencies: {
      '@noble/ciphers': '^2.3.0',
      '@noble/curves': '^2.3.0',
      '@noble/hashes': '^2.3.0',
      '@noble/post-quantum': '^0.7.1',
    },
    peerDependencies: { hpke: '^1.0.0' },
  }
  const files = {
    'LICENSE.md': 'MIT\n',
    'README.md': '# Noble suite\n',
    'index.d.ts': 'export declare const value: number\n',
    'index.js': 'export const value = 1\n',
    'source.ts': '// Not included in the npm package.\nexport const value = 1\n',
  }
  for (const target of [baseline, directory]) {
    writeJson(join(target, 'package.json'), noble)
    for (const [name, contents] of Object.entries(files)) {
      writeFileSync(join(target, name), contents)
    }
  }

  const rootManifest = join(temporary, 'package.json')
  writeJson(rootManifest, {
    name: 'example-hpke',
    version: rootVersion,
    devDependencies: noble.dependencies,
  })
  return { baseline, directory, rootManifest }
}

function sync(fixture) {
  return syncNobleVersion({
    baseline: `file:${fixture.baseline}`,
    directory: fixture.directory,
    log() {},
    rootManifest: fixture.rootManifest,
  })
}

test.describe('noble package version synchronization', () => {
  it('keeps the version when only unpublished source changes', (t) => {
    const current = fixture(t)
    const manifestPath = join(current.directory, 'package.json')
    const before = readFileSync(manifestPath, 'utf8')
    writeFileSync(join(current.directory, 'source.ts'), 'export const value = 2\n')

    assert.equal(sync(current).changed, false)
    assert.equal(readFileSync(manifestPath, 'utf8'), before)
  })

  it('syncs noble dependency ranges and bumps the version for dependency-only changes', (t) => {
    const current = fixture(t)
    const manifestPath = join(current.directory, 'package.json')
    const noble = JSON.parse(readFileSync(manifestPath, 'utf8'))
    noble.dependencies.unrelated = '^1.0.0'
    for (const directory of [current.baseline, current.directory]) {
      writeJson(join(directory, 'package.json'), noble)
    }
    const hpke = JSON.parse(readFileSync(current.rootManifest, 'utf8'))
    Object.assign(hpke.devDependencies, {
      '@noble/ciphers': '^2.4.0',
      '@noble/curves': '^2.4.0',
      '@noble/hashes': '^2.4.0',
      '@noble/unused': '^1.0.0',
      unrelated: '^2.0.0',
      typescript: '^6.0.3',
    })
    writeJson(current.rootManifest, hpke)

    const result = sync(current)

    assert.equal(result.changed, true)
    assert.deepEqual(result.changes, ['package.json'])
    assert.equal(result.previousVersion, '1.0.0')
    assert.equal(result.targetVersion, '2.0.0')
    assert.deepEqual(JSON.parse(readFileSync(manifestPath, 'utf8')), {
      ...noble,
      version: '2.0.0',
      dependencies: {
        ...noble.dependencies,
        '@noble/ciphers': '^2.4.0',
        '@noble/curves': '^2.4.0',
        '@noble/hashes': '^2.4.0',
      },
    })
  })

  it('keeps the version when synchronized dependencies match the published artifact', (t) => {
    const current = fixture(t)
    const manifestPath = join(current.directory, 'package.json')
    const noble = JSON.parse(readFileSync(manifestPath, 'utf8'))
    noble.dependencies['@noble/ciphers'] = '^2.2.0'
    writeJson(manifestPath, noble)

    const result = sync(current)

    assert.equal(result.changed, false)
    assert.equal(result.targetVersion, '1.0.0')
    assert.equal(
      readFileSync(manifestPath, 'utf8'),
      readFileSync(join(current.baseline, 'package.json'), 'utf8'),
    )
  })

  it('rejects a noble dependency missing from the root without changing the manifest', (t) => {
    const current = fixture(t)
    const manifestPath = join(current.directory, 'package.json')
    const before = readFileSync(manifestPath, 'utf8')
    const hpke = JSON.parse(readFileSync(current.rootManifest, 'utf8'))
    hpke.devDependencies['@noble/ciphers'] = '^2.4.0'
    delete hpke.devDependencies['@noble/curves']
    writeJson(current.rootManifest, hpke)

    assert.throws(() => sync(current), /missing root devDependency for @noble\/curves/)
    assert.equal(readFileSync(manifestPath, 'utf8'), before)
  })

  const driftCases = [
    ['runtime JavaScript', 'index.js', 'export const value = 2\n'],
    ['TypeScript declarations', 'index.d.ts', 'export declare const value: string\n'],
    ['README', 'README.md', '# Changed noble suite\n'],
    ['license', 'LICENSE.md', 'Different license text\n'],
  ]
  for (const [label, name, contents] of driftCases) {
    it(`bumps the version for ${label} drift`, (t) => {
      const current = fixture(t)
      writeFileSync(join(current.directory, name), contents)

      const result = sync(current)

      assert.equal(result.changed, true)
      assert.equal(result.previousVersion, '1.0.0')
      assert.equal(result.targetVersion, '2.0.0')
      assert.equal(
        JSON.parse(readFileSync(join(current.directory, 'package.json'), 'utf8')).version,
        '2.0.0',
      )
    })
  }

  it('bumps the version for package manifest drift', (t) => {
    const current = fixture(t)
    const manifestPath = join(current.directory, 'package.json')
    const noble = JSON.parse(readFileSync(manifestPath, 'utf8'))
    noble.dependencies.dependency = '^2.0.0'
    writeJson(manifestPath, noble)

    assert.equal(sync(current).changed, true)
    assert.equal(JSON.parse(readFileSync(manifestPath, 'utf8')).version, '2.0.0')
  })

  it('bumps the version when a packed file is removed', (t) => {
    const current = fixture(t)
    rmSync(join(current.directory, 'index.d.ts'))

    assert.equal(sync(current).changed, true)
  })

  it('rejects unpublished drift when the target version is already in use', (t) => {
    const current = fixture(t, '1.0.0')
    writeFileSync(join(current.directory, 'index.js'), 'export const value = 2\n')

    assert.throws(() => sync(current), /already uses the target version/)
    assert.equal(
      JSON.parse(readFileSync(join(current.directory, 'package.json'), 'utf8')).version,
      '1.0.0',
    )
  })

  it('restores the manifest when dependency changes cannot use the target version', (t) => {
    const current = fixture(t, '1.0.0')
    const manifestPath = join(current.directory, 'package.json')
    const before = readFileSync(manifestPath, 'utf8')
    const hpke = JSON.parse(readFileSync(current.rootManifest, 'utf8'))
    hpke.devDependencies['@noble/ciphers'] = '^2.4.0'
    writeJson(current.rootManifest, hpke)

    assert.throws(() => sync(current), /already uses the target version/)
    assert.equal(readFileSync(manifestPath, 'utf8'), before)
  })

  it('leaves the manifest unchanged when the published artifact cannot be read', (t) => {
    const current = fixture(t)
    const manifestPath = join(current.directory, 'package.json')
    const before = readFileSync(manifestPath, 'utf8')
    const hpke = JSON.parse(readFileSync(current.rootManifest, 'utf8'))
    hpke.devDependencies['@noble/ciphers'] = '^2.4.0'
    writeJson(current.rootManifest, hpke)
    assert.throws(
      () =>
        syncNobleVersion({
          baseline: 'file:/does/not/exist',
          directory: current.directory,
          log() {},
          rootManifest: current.rootManifest,
          stderr: 'ignore',
        }),
      /failed to compare/,
    )
    assert.equal(readFileSync(manifestPath, 'utf8'), before)
  })
})
