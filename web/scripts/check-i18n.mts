// Checks the console's translations and how the code reads them.
//
// 1. zh-CN, zh-TW and en-US have the same keys, and every message is of the
//    same kind (text or function of the same arity) in all of them.
// 2. No code outside src/i18n/ reads `t` while a module loads: such a value is
//    frozen in the language of that moment and does not follow a switch.
// 3. No Chinese text outside src/i18n/ (and the files listed below): all copy
//    lives in the translation files.
import fs from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import zhCN from '../src/i18n/zh-CN.ts'
import zhTW from '../src/i18n/zh-TW.ts'
import enUS from '../src/i18n/en-US.ts'

const root = path.resolve(import.meta.dirname, '..')
const problems: string[] = []

// 1. same keys, same kinds -------------------------------------------------------
type Shape = Map<string, string>
function shape(v: unknown, at = '', out: Shape = new Map()): Shape {
  if (typeof v === 'function') out.set(at, `function/${v.length}`)
  else if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const [k, x] of Object.entries(v)) shape(x, at ? `${at}.${k}` : k, out)
  } else out.set(at, Array.isArray(v) ? 'array' : typeof v)
  return out
}
const ref = shape(zhCN)
for (const [name, msgs] of [['zh-TW', zhTW], ['en-US', enUS]] as const) {
  const s = shape(msgs)
  for (const [k, kind] of ref) {
    if (!s.has(k)) problems.push(`${name}: missing ${k}`)
    else if (s.get(k) !== kind) problems.push(`${name}: ${k} is ${s.get(k)}, zh-CN has ${kind}`)
  }
  for (const k of s.keys()) if (!ref.has(k)) problems.push(`${name}: extra key ${k}`)
}
// Han characters and CJK / full-width punctuation (such as （）「」：、)
const han = /[\u3000-\u303f\u3400-\u9fff\uf900-\ufaff\uff00-\uffef]/
// in a regular expression, full-width punctuation is input it accepts (a ， separator), not copy
const hanIdeographs = /[\u3400-\u9fff\uf900-\ufaff]/
for (const [k, kind] of shape(enUS)) {
  if (kind !== 'string') continue
  const v = k.split('.').reduce<any>((o, p) => o?.[p], enUS)
  if (han.test(v)) problems.push(`en-US: ${k} contains Chinese: ${JSON.stringify(v)}`)
}

// 2 and 3. the source ------------------------------------------------------------
// Files allowed to hold Chinese text: data (not copy) that must match Chinese input.
const chineseAllowed = new Set<string>([
  'src/lib/secretName.ts', // the secret-name keywords, mirrored from internal/secretscan
])

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) walk(p, out)
    else if (/\.(ts|tsx)$/.test(e.name)) out.push(p)
  }
  return out
}

const isFunctionLike = (n: ts.Node) =>
  ts.isFunctionLike(n) || ts.isClassStaticBlockDeclaration(n)

for (const file of walk(path.join(root, 'src'))) {
  const rel = path.relative(root, file).split(path.sep).join('/')
  if (rel.startsWith('src/i18n/')) continue
  const text = fs.readFileSync(file, 'utf8')
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, rel.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)

  // the local name `t` is bound to, when imported from @/i18n
  let local: string | null = null
  for (const st of sf.statements) {
    if (!ts.isImportDeclaration(st) || !ts.isStringLiteral(st.moduleSpecifier)) continue
    if (!/^(@\/i18n|.*\/i18n(\/index)?(\.ts)?)$/.test(st.moduleSpecifier.text)) continue
    const nb = st.importClause?.namedBindings
    if (nb && ts.isNamedImports(nb)) {
      for (const el of nb.elements) if ((el.propertyName ?? el.name).text === 't') local = el.name.text
    }
  }

  const visit = (n: ts.Node, inFn: boolean) => {
    if (local && !inFn && ts.isIdentifier(n) && n.text === local) {
      const p = n.parent
      const isDecl = ts.isImportSpecifier(p) || (ts.isPropertyAccessExpression(p) && p.name === n) || (ts.isPropertyAssignment(p) && p.name === n)
      if (!isDecl) {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart())
        problems.push(`${rel}:${line + 1}: reads t while the module loads (move it into a function or component)`)
      }
    }
    if (!chineseAllowed.has(rel) && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n) || ts.isJsxText(n) || ts.isRegularExpressionLiteral(n))) {
      if ((ts.isRegularExpressionLiteral(n) ? hanIdeographs : han).test(n.getText())) {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart())
        problems.push(`${rel}:${line + 1}: Chinese text outside src/i18n: ${n.getText().slice(0, 60)}`)
      }
    }
    ts.forEachChild(n, (c) => visit(c, inFn || isFunctionLike(n)))
  }
  visit(sf, false)
}

for (const p of problems) console.log(p)
console.log(`${problems.length} problem(s)`)
if (problems.length) process.exit(1)
