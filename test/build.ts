import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { test } from 'node:test'
import { runInNewContext } from 'node:vm'

const { cleanJavaScript }: { cleanJavaScript(code: string): string } = createRequire(
  import.meta.url,
)('../tools/clean-javascript.cjs')

const cases = [
  {
    name: 'URLs in strings',
    source: 'const url = "https://example.test/path//tail"; // remove\nurl',
  },
  {
    name: 'regular expression literals',
    source: String.raw`const pattern = /https?:\/\/example\.test\/\//; pattern.test("https://example.test//")`,
  },
  {
    name: 'regular expression character classes',
    source: 'const pattern = /[/*]/; pattern.test("*")',
  },
  {
    name: 'template literal contents and whitespace',
    source: 'const text = `first // literal\n  /** literal */\n   \nlast   `;\ntext',
  },
  {
    name: 'comments in template substitutions',
    source: 'const text = `value: ${/* remove */ 42}`; text',
  },
  {
    name: 'division and token separation',
    source: 'let value = 12 / /* remove */ 3; value/**/++; value',
  },
  {
    name: 'automatic semicolon insertion',
    source: 'function value() { return /* remove\nremove */ 42 }\nString(value())',
  },
  {
    name: 'comment markers inside strings',
    source: 'const text = "/* @__PURE__ */ // literal"; text',
  },
  { name: 'CRLF line breaks', source: 'const value = 42; /* remove\r\nremove */\r\nvalue' },
  {
    name: 'Unicode line separators',
    source: 'const value = 42; /* remove\u2028remove\u2029remove */ value',
  },
]

for (const { name, source } of cases) {
  test(`build cleanup preserves ${name}`, () => {
    const output = cleanJavaScript(source)
    assert.equal(runInNewContext(output), runInNewContext(source))
    assert.equal(
      output.split(/\r\n|[\r\n\u2028\u2029]/).length,
      source.split(/\r\n|[\r\n\u2028\u2029]/).length,
    )
  })
}

test('build cleanup removes comments while preserving PURE annotations', () => {
  const source = [
    '/** documentation */',
    'const value = /* @__PURE__ */ (() => {',
    '  // explanation',
    '  return /* explanation */ 42',
    '})()',
    'value',
  ].join('\n')
  const output = cleanJavaScript(source)
  assert.doesNotMatch(output, /documentation|explanation/)
  assert.ok(output.includes('/* @__PURE__ */'))
  assert.equal(runInNewContext(output), 42)
  assert.equal(output.split('\n').length, source.split('\n').length)
})

test('build cleanup retains bundler and legal directives', () => {
  for (const directive of [
    '/*#__PURE__*/',
    '/* @__NO_SIDE_EFFECTS__ */',
    '/*! retained notice */',
    '/* @license retained notice */',
    '// @preserve retained notice',
  ]) {
    const output = cleanJavaScript(`${directive}\n42`)
    assert.ok(output.includes(directive))
    assert.equal(runInNewContext(output), 42)
  }
})

test('build cleanup rejects invalid JavaScript', () => {
  assert.throws(() => cleanJavaScript('const ='), SyntaxError)
})
