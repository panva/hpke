import { type Application } from 'typedoc'
import { MarkdownPageEvent, MarkdownTheme, MarkdownThemeContext } from 'typedoc-plugin-markdown'

class MyMarkdownTheme extends MarkdownTheme {
  // @ts-ignore
  getRenderContext(page) {
    const ctx = new MarkdownThemeContext(this, page, this.application.options)
    {
      const orig = ctx.partials.typeArguments
      ctx.partials.typeArguments = function (typeArguments, options) {
        // @ts-ignore
        if (typeArguments[0]?.name === 'ArrayBufferLike') return ''
        // @ts-ignore
        return orig.call(this, typeArguments, options)
      }
    }

    const sources = ctx.partials.sources
    ctx.partials.sources = function (...args) {
      const src = sources.call(this, args[0])
      return `[source]${src.slice(src.indexOf(']') + 1)}`
    }

    return ctx
  }
  render(page: MarkdownPageEvent): string {
    const res = super.render(page)

    return res
      .replaceAll(
        `## Constructors

### Constructor`,
        '## Constructor',
      )
      .replaceAll('\\| `string` & \\{ \\}', '')
      .replaceAll('\\| `string` & `object`', '')
      .replaceAll(`\\|`, '∣')
      .replaceAll(/\| `options\?` \| \\{[^\|]+\\} \|/g, '\| `options?` \|  \|')
  }
}

export function load(app: Application) {
  app.renderer.defineTheme('my-markdown', MyMarkdownTheme)
}
