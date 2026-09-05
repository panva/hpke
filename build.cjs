const fs = require('node:fs')
const amaro = require('amaro')
const { gzipSync } = require('node:zlib')
const { execSync } = require('node:child_process')
const { cleanJavaScript } = require('./tools/clean-javascript.cjs')

// ============================================================================
// Compile TypeScript
// ============================================================================

execSync('npx tsc', { stdio: 'inherit' })
execSync('npx tsc -p ./examples/noble-suite', { stdio: 'inherit' })

// ============================================================================
// Process index.js
// ============================================================================

// Transform TypeScript to JavaScript, stripping type annotations only
const source = fs.readFileSync('./index.ts', 'utf8')
let js = amaro.transformSync(source, { mode: 'strip-only' }).code

fs.writeFileSync('index.js', js)
const indexJsBefore = getFileSizes('index.js')

js = cleanJavaScript(js)
checkPureAnnotations(source, js)

fs.writeFileSync('index.js', js)

const indexJsAfter = getFileSizes('index.js')
printSizes('index.js', indexJsBefore, indexJsAfter)

// Verify that index.js is valid JavaScript by requiring it
try {
  require('./index.js')
} catch (cause) {
  throw new Error('index.js is not valid javascript', { cause })
}

// ============================================================================
// Process index.d.ts
// ============================================================================

// Verify that index.d.ts and index.d.ts.map exist
if (!fs.existsSync('index.d.ts')) {
  throw new Error('index.d.ts not found')
}
if (!fs.existsSync('index.d.ts.map')) {
  throw new Error('index.d.ts.map not found')
}

// Clean up TypeScript declaration file
let dts = fs.readFileSync('index.d.ts', 'utf8')

const indexDtsBefore = { uncompressed: dts.length, compressed: gzipSync(dts).length }

// Remove @example blocks including their code samples and the trailing comment line
// Replace with equivalent blank lines to preserve line numbers
dts = dts.replace(/[ \t]*\*[ \t]*@example[\s\S]*?```\n[ \t]*\*[ \t]*\n/g, (match) => {
  const lineCount = (match.match(/\n/g) || []).length
  return '\n'.repeat(lineCount)
})

fs.writeFileSync('index.d.ts', dts)

const indexDtsAfter = getFileSizes('index.d.ts')
printSizes('index.d.ts', indexDtsBefore, indexDtsAfter)

// ============================================================================
// @panva/hpke-noble
// ============================================================================

{
  const inFile = './examples/noble-suite/index.ts'
  const outFile = './examples/noble-suite/index.js'
  const source = fs.readFileSync(inFile, 'utf8')
  let js = amaro.transformSync(source, { mode: 'strip-only' }).code

  // Rewrite import paths from '../../index.ts' to 'hpke'
  js = js.replace(/(['"])\.\.\/\.\.\/index\.ts\1/g, "'hpke'")

  fs.writeFileSync(outFile, js)
  const nobleBefore = getFileSizes(outFile)

  js = cleanJavaScript(js)
  checkPureAnnotations(source, js)

  fs.writeFileSync(outFile, js)

  const nobleAfter = getFileSizes(outFile)
  printSizes('examples/noble-suite/index.js', nobleBefore, nobleAfter)
}

{
  const file = './examples/noble-suite/index.d.ts'
  let dts = fs.readFileSync(file, 'utf8')

  // Rewrite import paths from '../../index.ts' to 'hpke'
  dts = dts.replace(/(['"])\.\.\/\.\.\/index\.ts\1/g, "'hpke'")

  fs.writeFileSync(file, dts)
}

// ============================================================================
// Utils
// ============================================================================

function checkPureAnnotations(source, output) {
  // Both type stripping and comment cleanup must preserve bundler annotations.
  const annotation = /\/\*\s*[@#]__PURE__\s*\*\//g
  if ((source.match(annotation)?.length ?? 0) !== (output.match(annotation)?.length ?? 0)) {
    throw new Error('Build must preserve PURE annotations')
  }
}

function getFileSizes(path) {
  const content = fs.readFileSync(path)
  const uncompressed = content.length
  const compressed = gzipSync(content).length
  return { uncompressed, compressed }
}

function formatSize(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`
}

function printSizes(label, before, after) {
  console.log(`${label}:`)
  console.log(
    `  Uncompressed: ${formatSize(before.uncompressed)} → ${formatSize(after.uncompressed)} (${(((after.uncompressed - before.uncompressed) / before.uncompressed) * 100).toFixed(1)}%)`,
  )
  console.log(
    `  Compressed:   ${formatSize(before.compressed)} → ${formatSize(after.compressed)} (${(((after.compressed - before.compressed) / before.compressed) * 100).toFixed(1)}%)`,
  )
  console.log()
}
