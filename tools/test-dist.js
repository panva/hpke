// Validates the exact npm artifacts rather than only the working-tree source. Each tarball is
// installed in isolation so missing files and undeclared runtime imports fail before publication.
//
// With no arguments, both publishable packages are packed from the working tree and checked. The
// release workflow instead supplies its already-created tarball and the corresponding manifest
// directory, ensuring the artifact that passes this check is the one that gets published.
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { noblePackageDrift } from './sync-noble-version.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'

const configurations = new Map([
  [
    'hpke',
    {
      directory: '.',
      files: [
        'LICENSE.md',
        'README.md',
        'index.d.ts',
        'index.d.ts.map',
        'index.js',
        'index.ts',
        'package.json',
      ],
      exports: ['AEAD_AES_128_GCM', 'CipherSuite', 'KDF_HKDF_SHA256', 'KEM_DHKEM_P256_HKDF_SHA256'],
      tagged: true,
    },
  ],
  [
    '@panva/hpke-noble',
    {
      directory: 'examples/noble-suite',
      files: ['LICENSE.md', 'README.md', 'index.d.ts', 'index.js', 'package.json'],
      exports: [
        'AEAD_AES_128_GCM',
        'AEAD_ChaCha20Poly1305',
        'KDF_HKDF_SHA256',
        'KDF_SHAKE256',
        'KDF_TurboSHAKE256',
        'KEM_DHKEM_P256_HKDF_SHA256',
        'KEM_DHKEM_X25519_HKDF_SHA256',
        'KEM_ML_KEM_768',
        'KEM_MLKEM768_X25519',
      ],
      tagged: false,
    },
  ],
])

function run(command, args, cwd = root) {
  execFileSync(command, args, { cwd, stdio: 'inherit' })
}

function manifest(directory) {
  return JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
}

function checkPackageVersions() {
  const hpke = manifest(root)
  const nobleDirectory = join(root, 'examples/noble-suite')
  const noble = manifest(nobleDirectory)
  if (hpke.version === noble.version) return

  const drift = noblePackageDrift({ directory: nobleDirectory })
  if (drift.changed) {
    throw new Error(
      `package versions differ: ${hpke.name}@${hpke.version} and ${noble.name}@${noble.version}. ` +
        `${noble.name} also differs from its published ${noble.version} artifact in ` +
        drift.changes.join(', '),
    )
  }
  console.log(
    `validated ${hpke.name}@${hpke.version} as a core-only release; ` +
      `${noble.name}@${noble.version} is unchanged`,
  )
}

function createTarball(directory, destination) {
  mkdirSync(destination, { recursive: true })
  run(npm, ['pack', resolve(root, directory), '--pack-destination', destination])
  const tarballs = readdirSync(destination).filter((entry) => entry.endsWith('.tgz'))
  if (tarballs.length !== 1) {
    throw new Error(`npm pack produced ${tarballs.length} tarballs for ${directory}`)
  }
  return join(destination, tarballs[0])
}

function listPackageFiles(directory, prefix = '') {
  const files = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    // Dependencies are installed only for the runtime smoke test and are not part of the tarball's
    // own file contract.
    if (prefix === '' && entry.name === 'node_modules') continue
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      files.push(...listPackageFiles(join(directory, entry.name), relative))
    } else {
      files.push(relative)
    }
  }
  return files
}

function validateTarball(tarball, manifestDirectory, staging, checkTag = false) {
  const source = manifest(manifestDirectory)
  const configuration = configurations.get(source.name)
  if (!configuration || resolve(root, configuration.directory) !== manifestDirectory) {
    throw new Error(`unsupported package manifest: ${manifestDirectory}`)
  }

  const isolated = join(staging, source.name.replaceAll('/', '-').replaceAll('@', ''))
  mkdirSync(isolated)
  writeFileSync(
    join(isolated, 'package.json'),
    JSON.stringify({ name: 'hpke-artifact-validation', private: true, type: 'module' }),
  )
  run(
    npm,
    [
      'install',
      '--install-strategy=hoisted',
      '--omit=dev',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      tarball,
    ],
    isolated,
  )

  const installed = join(isolated, 'node_modules', ...source.name.split('/'))
  const packed = manifest(installed)
  if (packed.name !== source.name || packed.version !== source.version) {
    throw new Error('the package tarball does not match the checked-out package name and version')
  }

  if (
    checkTag &&
    configuration.tagged &&
    process.env.GITHUB_REF_NAME !== undefined &&
    process.env.GITHUB_REF_NAME !== `v${packed.version}`
  ) {
    throw new Error(
      `release tag ${process.env.GITHUB_REF_NAME} does not match ${packed.name}@${packed.version}`,
    )
  }

  const actualFiles = listPackageFiles(installed).sort()
  if (JSON.stringify(actualFiles) !== JSON.stringify(configuration.files)) {
    throw new Error(
      `packed files differ for ${source.name}\n` +
        `expected: ${configuration.files.join(', ')}\n` +
        `actual:   ${actualFiles.join(', ')}`,
    )
  }

  writeFileSync(
    join(isolated, 'smoke.mjs'),
    `import * as api from ${JSON.stringify(source.name)}
for (const name of ${JSON.stringify(configuration.exports)}) {
  if (typeof api[name] !== 'function') throw new Error(\`missing export \${name}\`)
}

const core = ${source.name === 'hpke' ? 'api' : "await import('hpke')"}
const suite = new core.CipherSuite(
  api.KEM_DHKEM_P256_HKDF_SHA256,
  api.KDF_HKDF_SHA256,
  api.AEAD_AES_128_GCM,
)
const recipient = await suite.GenerateKeyPair()
const plaintext = new Uint8Array([1, 2, 3, 4])
const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient.publicKey, plaintext)
const opened = await suite.Open(recipient, encapsulatedSecret, ciphertext)
if (opened.length !== plaintext.length || opened.some((byte, index) => byte !== plaintext[index])) {
  throw new Error('packed artifact HPKE roundtrip failed')
}
`,
  )
  run(process.execPath, ['smoke.mjs'], isolated)
  console.log(
    `validated ${basename(tarball)} as ${packed.name}@${packed.version} containing ${actualFiles.join(', ')}`,
  )
}

const [suppliedTarball, suppliedManifestDirectory, ...extraArguments] = process.argv.slice(2)
if (extraArguments.length !== 0 || (suppliedManifestDirectory !== undefined && !suppliedTarball)) {
  throw new Error('expected a package tarball followed by its manifest directory')
}
const resolvedManifestDirectory = resolve(root, suppliedManifestDirectory ?? '.')

const staging = mkdtempSync(join(tmpdir(), 'hpke-dist-'))
try {
  if (suppliedTarball) {
    // Pending noble changes are valid during development; enforce the version decision only for
    // the root release artifact.
    if (resolvedManifestDirectory === root) checkPackageVersions()
    validateTarball(resolve(root, suppliedTarball), resolvedManifestDirectory, staging, true)
  } else {
    run(npm, ['run', 'build'])
    for (const configuration of configurations.values()) {
      const destination = join(staging, configuration.directory.replaceAll('/', '-'))
      const tarball = createTarball(configuration.directory, destination)
      validateTarball(tarball, resolve(root, configuration.directory), staging)
    }
  }
} finally {
  rmSync(staging, { recursive: true, force: true })
}
