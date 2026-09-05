const ts = require('typescript')

function cleanJavaScript(code) {
  const source = ts.createSourceFile(
    'input.js',
    code,
    ts.ScriptTarget.Latest,
    false,
    ts.ScriptKind.JS,
  )
  if (source.parseDiagnostics.length !== 0) {
    throw new SyntaxError('Invalid JavaScript input')
  }

  const comments = new Map()
  function visit(node) {
    if (node.kind === ts.SyntaxKind.JSDocComment) return

    for (const range of ts.getLeadingCommentRanges(code, node.pos) ?? []) {
      comments.set(range.pos, range)
    }
    for (const range of ts.getTrailingCommentRanges(code, node.end) ?? []) {
      comments.set(range.pos, range)
    }
    for (const child of node.getChildren(source)) visit(child)
  }
  visit(source)

  let output = ''
  let offset = 0
  for (const { pos, end } of [...comments.values()].sort((left, right) => left.pos - right.pos)) {
    const comment = code.slice(pos, end)
    if (
      /^\/\*\s*[@#]__(?:PURE|NO_SIDE_EFFECTS)__\s*\*\/$/.test(comment) ||
      comment.startsWith('/*!') ||
      /@(?:license|preserve)\b/.test(comment)
    ) {
      continue
    }
    output += code.slice(offset, pos)
    output += comment.replace(/[^\r\n\u2028\u2029]/g, '') || ' '
    offset = end
  }
  return output + code.slice(offset)
}

module.exports = { cleanJavaScript }
