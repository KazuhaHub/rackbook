import { displayId, idParts } from '../src/lib/recordId.ts'
import { isGeneric, parseTabHash, splitGeneric, tabHash, type GenericRule } from '../src/lib/backrefs.ts'
import { filterRows, paginate, parsePageSize } from '../src/lib/tableView.ts'
import {
  fieldKind,
  inlineKind,
  listEntryError,
  portEntryError,
  suggestOption,
  suggestValues,
  PORT_PATTERN,
} from '../src/lib/fieldKind.ts'
import { customFormats } from '../src/lib/formats.ts'

let failed = 0
function eq(name: string, got: unknown, want: unknown) {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error('FAIL', name, '\n  got ', JSON.stringify(got), '\n  want', JSON.stringify(want))
    failed++
  }
}

// ids as people read them
eq('id plain', displayId('web-1/SSH'), 'web-1 / SSH')
eq('id slash', displayId('1Panel %2F aaPanel 面板'), '1Panel / aaPanel 面板')
eq('id percent', displayId('50%25 of a%2Fb'), '50% of a/b')
eq('id double escape', displayId('a%252Fb'), 'a%2Fb')
eq('id lowercase', displayId('a%2fb'), 'a/b')
eq('id parts', idParts('x%2Fy/z'), ['x/y', 'z'])
eq('id single', displayId('only'), 'only')

// own vs general backref records
const rules: GenericRule[] = [{ field: 'used_by', allow: ['all'], parentValue: 'dev-1' }]
const recs = [
  { id: '1', data: { used_by: ['all'] } },
  { id: '2', data: { used_by: ['dev-1', 'dev-2'] } },
  { id: '3', data: { used_by: ['all', 'dev-1'] } },
  { id: '4', data: { used_by: [] } },
  { id: '5', data: {} },
  { id: '6', data: { used_by: ['dev-2'] } },
]
const s = splitGeneric(recs, rules)
eq('generic ids', s.generic.map((r) => r.id), ['1'])
eq('own ids', s.own.map((r) => r.id), ['2', '3', '4', '5', '6'])
eq('scalar literal', isGeneric({ device: 'all' }, [{ field: 'device', allow: ['all'], parentValue: 'x' }]), true)
eq('scalar own', isGeneric({ device: 'x' }, [{ field: 'device', allow: ['all'], parentValue: 'x' }]), false)
eq('no allow', isGeneric({ device: 'all' }, [{ field: 'device', allow: [], parentValue: 'x' }]), false)
eq('literal is the parent', isGeneric({ device: 'all' }, [{ field: 'device', allow: ['all'], parentValue: 'all' }]), false)
for (const k of [
  { collection: 'credentials', generic: false },
  { collection: 'credentials', generic: true },
  { collection: 'a b/c+d', generic: true },
  { collection: '密钥', generic: false },
]) eq('tab hash ' + k.collection, parseTabHash(tabHash(k)), k)
eq('tab hash empty', parseTabHash(''), undefined)
eq('tab hash bad', parseTabHash('#%E0%A4%A'), undefined)

// search and paging
const rows = ['Alpha web', 'beta DB', 'alpha db', 'gamma']
eq('search all', filterRows(rows, (x) => x, ''), rows)
eq('search one', filterRows(rows, (x) => x, 'ALPHA'), ['Alpha web', 'alpha db'])
eq('search words', filterRows(rows, (x) => x, ' alpha  db '), ['alpha db'])
eq('search none', filterRows(rows, (x) => x, 'zzz'), [])
const many = Array.from({ length: 23 }, (_, i) => i + 1)
const p3 = paginate(many, 3, 10)
eq('page 3', [p3.items, p3.page, p3.pages, p3.from, p3.to, p3.total], [[21, 22, 23], 3, 3, 21, 23, 23])
eq('page clamp high', paginate(many, 9, 10).page, 3)
eq('page clamp low', paginate(many, 0, 10).page, 1)
const all = paginate(many, 2, 0)
eq('page all', [all.items.length, all.page, all.pages, all.from, all.to], [23, 1, 1, 1, 23])
const none = paginate([], 1, 10)
eq('page empty', [none.items.length, none.pages, none.from, none.to], [0, 1, 0, 0])
eq('page size ok', [parsePageSize('10'), parsePageSize('0'), parsePageSize('50')], [10, 0, 50])
eq('page size bad', [parsePageSize(null), parsePageSize(''), parsePageSize('7'), parsePageSize('x')], [25, 25, 25, 25])

// which widget a property gets
const ctx = { isKey: false, isRef: false }
eq('kind text', fieldKind({ type: 'string' }, ctx), 'suggest')
eq('kind nullable text', fieldKind({ type: ['string', 'null'] }, ctx), 'suggest')
eq('kind key', fieldKind({ type: 'string' }, { isKey: true, isRef: false }), 'plain')
eq('kind key forced', fieldKind({ type: 'string', 'x-rackbook': { suggest: true } }, { isKey: true, isRef: false }), 'suggest')
eq('kind ref', fieldKind({ type: 'string' }, { isKey: false, isRef: true }), 'plain')
eq('kind suggest off', fieldKind({ type: 'string', 'x-rackbook': { suggest: false } }, ctx), 'plain')
eq('kind format', fieldKind({ type: 'string', format: 'ipv4' }, ctx), 'plain')
eq('kind format forced', fieldKind({ type: 'string', format: 'ipv4', 'x-rackbook': { suggest: true } }, ctx), 'suggest')
eq('kind pattern', fieldKind({ type: 'string', pattern: '^a' }, ctx), 'plain')
eq('kind textarea', fieldKind({ type: 'string', format: 'textarea' }, ctx), 'textarea')
eq('kind date', fieldKind({ type: ['string', 'null'], format: 'date' }, ctx), 'date')
eq('kind enum', fieldKind({ type: 'string', enum: ['a', 'b'] }, ctx), 'enum')
eq('kind enum+null', fieldKind({ type: ['string', 'null'], enum: ['a', null] }, ctx), 'enum')
eq('kind number enum', fieldKind({ type: 'integer', enum: [1, 2] }, ctx), 'plain')
eq('kind bool', fieldKind({ type: 'boolean' }, ctx), 'boolean')
eq('kind tags', fieldKind({ type: 'array', uniqueItems: true, items: { type: 'string', enum: ['x', 'y'] } }, ctx), 'tags')
eq('kind list', fieldKind({ type: 'array', items: { type: 'string', pattern: PORT_PATTERN } }, ctx), 'list')
eq('kind object list', fieldKind({ type: 'array', items: { type: 'object' } }, ctx), 'plain')
eq('kind integer', fieldKind({ type: 'integer' }, ctx), 'plain')
eq('suggest option', [suggestOption({ 'x-rackbook': { suggest: false } }), suggestOption({}), suggestOption({ 'x-rackbook': { suggest: 'no' } })], [false, undefined, undefined])
eq('inline enum', inlineKind({ type: 'string', enum: ['a'] }, ctx), 'enum')
eq('inline key', inlineKind({ type: 'string', enum: ['a'] }, { isKey: true, isRef: false }), null)
eq('inline ref', inlineKind({ type: 'string', enum: ['a'] }, { isKey: false, isRef: true }), null)
eq('inline text', inlineKind({ type: 'string' }, ctx), null)
eq('inline tags', inlineKind({ type: 'array', items: { type: 'string', enum: ['a'] } }, ctx), 'tags')
eq('inline date', inlineKind({ type: 'string', format: 'date' }, ctx), 'date')

// suggestions come from the values in use, most used first
const sr = [
  { data: { os: 'Debian' } },
  { data: { os: 'Ubuntu' } },
  { data: { os: 'Debian' } },
  { data: { os: '' } },
  { data: { os: null } },
  { data: {} },
  { data: { os: 'Alpine' } },
]
eq('suggest values', suggestValues(sr, 'os'), ['Debian', 'Alpine', 'Ubuntu'])
eq('suggest limit', suggestValues(sr, 'os', 1), ['Debian'])
eq('suggest none', suggestValues(sr, 'nope'), [])

// list entries and ports
const items = { type: 'string', pattern: PORT_PATTERN }
for (const ok of ['443', '20000-20018', '0', '65535', '1-65535']) eq('port ok ' + ok, listEntryError(items, ok, customFormats), undefined)
for (const bad of ['', 'abc', '70000', '1-70000', '90-80', '1-2-3', '443 ', '-5', '123456']) {
  eq('port bad ' + bad, typeof listEntryError(items, bad, customFormats), 'string')
}
eq('port hint', listEntryError(items, 'x', customFormats), '端口或范围，如 443、20000-20018')
eq('port description wins', listEntryError(items, 'x', customFormats, '端口号'), '端口号')
eq('port too big', portEntryError('65536'), '端口不能超过 65535')
eq('format entry', listEntryError({ type: 'string', format: 'ipv4' }, '10.0.0.1', customFormats), undefined)
eq('format entry bad', typeof listEntryError({ type: 'string', format: 'ipv4' }, '10.0.0', customFormats), 'string')
eq('plain entry', listEntryError({ type: 'string' }, 'anything', customFormats), undefined)

if (failed) process.exit(1)
console.log('console logic: ok')
