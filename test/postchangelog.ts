import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { test } from 'node:test'

const { formatChangelog } = createRequire(import.meta.url)('../tools/postchangelog.cjs') as {
  formatChangelog(changelog: string): string
}

test('formats and separates release headings', () => {
  const malformed = [
    '# Changelog',
    '',
    '### [2.0.0](new)',
    '',
    '* changed',
    '## [1.0.0](previous)',
    '',
    '* changed before',
    '## 0.9.0 (initial)',
    '',
  ].join('\n')
  const expected = [
    '# Changelog',
    '',
    '## [2.0.0](new)',
    '',
    '* changed',
    '',
    '## [1.0.0](previous)',
    '',
    '* changed before',
    '',
    '## 0.9.0 (initial)',
    '',
  ].join('\n')

  assert.equal(formatChangelog(malformed), expected)
  assert.equal(formatChangelog(expected), expected)
})

test('preserves CRLF newlines', () => {
  const malformed = '* changed\r\n## [1.0.0](previous)\r\n'
  const expected = '* changed\r\n\r\n## [1.0.0](previous)\r\n'

  assert.equal(formatChangelog(malformed), expected)
})
