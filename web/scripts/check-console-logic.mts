import { displayId, idParts } from '../src/lib/recordId.ts'
import { isGeneric, parseTabHash, pickTab, splitGeneric, tabHash, type GenericRule } from '../src/lib/backrefs.ts'
import { filterRows, paginate, parsePageSize } from '../src/lib/tableView.ts'
import {
  enumEntries,
  enumForm,
  enumValues,
  itemEnum,
  fieldKind,
  inlineKind,
  listEntryError,
  portEntryError,
  suggestOption,
  suggestValues,
  PORT_PATTERN,
} from '../src/lib/fieldKind.ts'
import { customFormats } from '../src/lib/formats.ts'
import { getAtPath, isLongValue, pointerSegments, restoreStep, setAtPath, shortHash, shortValue, unresolvedHidden, valueText } from '../src/lib/versionValue.ts'
import { isSecretName } from '../src/lib/secretName.ts'
import { formatItem, formatPlain, isScalarObject, objectItems } from '../src/lib/objectItems.ts'
import {
  backrefTitle,
  codeForLabel,
  collectionDescription,
  collectionGroup,
  collectionTitle,
  enumChoices,
  enumItemLabel,
  enumLabel,
  enumMatches,
  propAt,
  enumOption,
  enumOptions,
  fieldDefTitle,
  fieldDescription,
  fieldTitle,
  isEnumLike,
  ledgerTitle,
  noteTitle,
  refBackrefTitle,
} from '../src/lib/labels.ts'
import { displayText } from '../src/lib/display.ts'
import { issueText } from '../src/lib/issues.ts'
import { eventSentence } from '../src/lib/eventSentence.ts'
import { activateLocale } from '../src/i18n/index.ts'
import { countryName, flagEmoji, subdivisionCountry } from '../src/lib/countryDisplay.ts'
import { COUNTRY_CODES } from '../src/lib/countries.ts'

let failed = 0
function eq(name: string, got: unknown, want: unknown) {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error('FAIL', name, '\n  got ', JSON.stringify(got), '\n  want', JSON.stringify(want))
    failed++
  }
}

// ids as people read them
eq('id plain', displayId('web-1/SSH'), 'web-1 › SSH')
eq('id slash', displayId('1Panel %2F aaPanel 面板'), '1Panel / aaPanel 面板')
eq('id slash in a compound key', displayId('a%2Fb/c'), 'a/b › c')
eq('id separator char', displayId('a›b/c'), 'a\\›b › c')
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
eq('kind sole key', fieldKind({ type: 'string' }, { isKey: true, soleKey: true, isRef: false }), 'plain')
eq('kind compound key part', fieldKind({ type: 'string' }, { isKey: true, soleKey: false, isRef: false }), 'suggest')
eq('kind key forced', fieldKind({ type: 'string', 'x-rackbook': { suggest: true } }, { isKey: true, soleKey: true, isRef: false }), 'suggest')
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

// several rules on one collection: naming the record in any of them makes it its own
const two: GenericRule[] = [
  { field: 'a', allow: ['all'], parentValue: 'x' },
  { field: 'b', allow: ['all'], parentValue: 'x' },
]
eq('two rules: own via b', isGeneric({ a: 'all', b: 'x' }, two), false)
eq('two rules: own via a', isGeneric({ a: ['x'], b: 'all' }, two), false)
eq('two rules: general', isGeneric({ a: 'all', b: 'y' }, two), true)
eq('two rules: general via b', isGeneric({ a: 'y', b: ['all'] }, two), true)
eq('two rules: neither', isGeneric({ a: 'y', b: 'z' }, two), false)

// the tab a hash selects
const tabKeys = [
  { collection: 'services', generic: false },
  { collection: 'credentials', generic: false },
  { collection: 'credentials', generic: true },
]
eq('pick tab', pickTab('#credentials+generic', tabKeys), 2)
eq('pick tab own', pickTab('#credentials', tabKeys), 1)
eq('pick tab unknown collection', pickTab('#nope', tabKeys), 0)
eq('pick tab unknown generic', pickTab('#services+generic', tabKeys), 0)
eq('pick tab empty', pickTab('', tabKeys), 0)
eq('pick tab malformed', pickTab('#%E0%A4%A', tabKeys), 0)

// secret-named fields never get suggestions, whatever the option says
for (const n of ['password', 'db_password', 'client_secret', 'api_key', 'apiKey', 'authToken', 'tokens', 'psk', 'private-key', '密码', '访问密钥', 'wpa_passphrase']) {
  eq('secret name ' + n, isSecretName(n), true)
  eq('secret name not suggested ' + n, fieldKind({ type: 'string', 'x-rackbook': { suggest: true } }, { isKey: false, isRef: false, name: n }), 'plain')
}
for (const n of ['name', 'os', 'service', 'token_expiry_note', 'keyboard', 'passport']) eq('plain name ' + n, isSecretName(n), false)
eq('public field', fieldKind({ type: 'string', 'x-rackbook': { public: 'uuid', suggest: true } }, { isKey: false, isRef: false, name: 'x' }), 'plain')
eq('plain name keeps suggest', fieldKind({ type: 'string' }, { isKey: false, isRef: false, name: 'os' }), 'suggest')

// list entries: maxLength, an invalid regex in the schema, a format
eq('list maxLength ok', listEntryError({ type: 'string', maxLength: 3 }, 'abc', customFormats), undefined)
eq('list maxLength', listEntryError({ type: 'string', maxLength: 3 }, 'abcd', customFormats), '最多 3 个字符')
eq('list invalid regex is ignored', listEntryError({ type: 'string', pattern: '([' }, 'x', customFormats), undefined)
eq('list unknown format is ignored', listEntryError({ type: 'string', format: 'nope' }, 'x', customFormats), undefined)

// arrays of flat objects
const portsSchema = {
  type: 'array',
  items: {
    type: 'object',
    required: ['protocol', 'port'],
    properties: {
      protocol: { type: 'string', enum: ['TCP', 'UDP'] },
      port: { type: 'string', pattern: PORT_PATTERN },
      note: { type: 'string' },
    },
  },
}
const spec = objectItems(portsSchema)!
eq('object items found', spec.props.map(([n]) => n), ['protocol', 'port', 'note'])
eq('object items required', spec.required, ['protocol', 'port'])
eq('object items kind', fieldKind(portsSchema, { isKey: false, isRef: false }), 'rows')
eq('object items not inline', inlineKind(portsSchema, { isKey: false, isRef: false }), null)
eq('format item', formatItem({ protocol: 'TCP', port: '443' }, spec), { text: 'TCP 443', title: undefined })
eq('format item note', formatItem({ protocol: 'UDP', port: '443', note: 'quic' }, spec), { text: 'UDP 443', title: 'quic' })
eq('format item only note', formatItem({ note: 'x' }, spec), { text: 'x', title: undefined })
eq('format item empty', formatItem({}, spec), { text: '', title: undefined })
eq('format plain', formatPlain({ protocol: 'TCP', port: 443, note: null }), 'TCP 443')
eq('scalar object', [isScalarObject({ a: 1, b: 'x' }), isScalarObject({ a: { b: 1 } }), isScalarObject([1]), isScalarObject('x')], [true, false, false, false])
eq('nested object items are not flat', objectItems({ type: 'array', items: { type: 'object', properties: { a: { type: 'object' } } } }), undefined)
eq('array of strings is not object items', objectItems({ type: 'array', items: { type: 'string' } }), undefined)
eq('object without properties', objectItems({ type: 'array', items: { type: 'object' } }), undefined)

// the oneOf form of an enum (default-language titles in oneOf, other languages in x-rackbook-i18n)
const ipv4Type = {
  type: 'string',
  title: 'IPv4 类型',
  description: '地址的分配方式',
  oneOf: [{ const: 'static', title: '静态' }, { const: 'dynamic', title: '动态' }, { const: 'nat' }],
  'x-rackbook-i18n': {
    'en-US': { title: 'IPv4 type', description: 'How the address is assigned', enum: { static: 'Static', dynamic: 'Dynamic', nat: 'NAT' } },
    'zh-TW': { title: 'IPv4 類型', enum: { static: '靜態' } },
  },
  'x-rackbook-enum-icons': { static: 'pin', dynamic: 'refresh-cw' },
  'x-rackbook-enum-colors': { static: 'green' },
}
eq('oneOf kind', fieldKind(ipv4Type, ctx), 'enum')
eq('oneOf nullable kind', fieldKind({ ...ipv4Type, type: ['string', 'null'] }, ctx), 'enum')
eq('oneOf values', enumValues(ipv4Type), ['static', 'dynamic', 'nat'])
eq('oneOf entries', enumEntries(ipv4Type), [{ value: 'static', title: '静态' }, { value: 'dynamic', title: '动态' }, { value: 'nat' }])
eq('plain enum entries', enumEntries({ type: 'string', enum: ['a', 'b'] }), [{ value: 'a' }, { value: 'b' }])
eq('oneOf inline', inlineKind(ipv4Type, ctx), 'enum')
eq('oneOf is not an enum with extra keys', enumValues({ type: 'string', oneOf: [{ const: 'a', description: 'x' }] }), undefined)
eq('oneOf is not an enum with a non-string const', enumValues({ type: 'string', oneOf: [{ const: 1 }] }), undefined)
eq('oneOf is not an enum with a schema alternative', enumValues({ type: 'string', oneOf: [{ const: 'a' }, { pattern: '^b' }] }), undefined)
eq('oneOf of a number is not a string enum', enumValues({ type: 'integer', oneOf: [{ const: 'a' }] }), undefined)
eq('empty oneOf', enumValues({ type: 'string', oneOf: [] }), undefined)
const tagsOneOf = { type: 'array', items: { type: 'string', oneOf: [{ const: 'public', title: '公网' }, { const: 'lan', title: '局域网' }] } }
eq('oneOf tags kind', fieldKind(tagsOneOf, ctx), 'tags')
eq('oneOf tags values', itemEnum(tagsOneOf), ['public', 'lan'])
eq('oneOf tags inline', inlineKind(tagsOneOf, ctx), 'tags')
// what the form library gets: plain enum, the original kept for the labels
const formProp = enumForm(ipv4Type) as Record<string, unknown>
eq('form schema has enum', formProp.enum, ['static', 'dynamic', 'nat'])
eq('form schema has no oneOf', 'oneOf' in formProp, false)
eq('form schema keeps the labels', enumLabel(formProp, 'static', 'zh-CN'), '静态')
eq('form schema keeps the translations', enumLabel(formProp, 'static', 'en-US'), 'Static')
eq('form schema kind', fieldKind(formProp, ctx), 'enum')
eq('form schema leaves the original alone', 'oneOf' in ipv4Type, true)
eq('form schema plain enum unchanged', enumForm({ type: 'string', enum: ['a'] }), { type: 'string', enum: ['a'] })
const rowsOneOf = { type: 'array', items: { type: 'object', properties: { protocol: { type: 'string', oneOf: [{ const: 'tcp', title: 'TCP' }] }, port: { type: 'string' } } } }
const rowsForm = enumForm(rowsOneOf) as any
eq('form schema row enum', rowsForm.items.properties.protocol.enum, ['tcp'])
eq('form schema row has no oneOf', 'oneOf' in rowsForm.items.properties.protocol, false)
eq('form schema rows are still rows', fieldKind(rowsForm, ctx), 'rows')
eq('form schema array items', (enumForm(tagsOneOf) as any).items.enum, ['public', 'lan'])
eq('oneOf rows: an enum property is not a note', formatItem({ protocol: 'tcp', port: '1' }, objectItems(rowsOneOf)!), { text: 'tcp', title: '1' })

// labels: the language's translation, else the standard text, else the code
eq('label zh-CN is the standard text', enumLabel(ipv4Type, 'static', 'zh-CN'), '静态')
eq('label en-US', enumLabel(ipv4Type, 'dynamic', 'en-US'), 'Dynamic')
eq('label zh-TW translated', enumLabel(ipv4Type, 'static', 'zh-TW'), '靜態')
eq('label zh-TW falls back to the standard text', enumLabel(ipv4Type, 'dynamic', 'zh-TW'), '动态')
eq('label falls back to the code', enumLabel(ipv4Type, 'nat', 'zh-CN'), 'nat')
eq('label zh-TW code fallback', enumLabel(ipv4Type, 'nat', 'zh-TW'), 'nat')
eq('label of an unknown code', enumLabel(ipv4Type, 'wifi', 'en-US'), 'wifi')
eq('label of a plain enum', enumLabel({ type: 'string', enum: ['a'] }, 'a', 'en-US'), 'a')
eq('label of a non-enum', enumLabel({ type: 'string' }, 'x', 'en-US'), 'x')
eq('label ignores an empty translation', enumLabel({ ...ipv4Type, 'x-rackbook-i18n': { 'en-US': { enum: { static: '' } } } }, 'static', 'en-US'), '静态')
eq('label ignores an unsupported shape', enumLabel({ ...ipv4Type, 'x-rackbook-i18n': 'oops' }, 'static', 'en-US'), '静态')
eq('options en-US', enumOptions(ipv4Type, 'en-US'), [
  { value: 'static', label: 'Static', icon: 'pin', color: 'green' },
  { value: 'dynamic', label: 'Dynamic', icon: 'refresh-cw', color: undefined },
  { value: 'nat', label: 'NAT', icon: undefined, color: undefined },
])
eq('options of a plain enum', enumOptions({ type: 'string', enum: ['x', 'y'] }, 'en-US').map((o) => o.label), ['x', 'y'])
eq('options of a non-enum', enumOptions({ type: 'string' }, 'en-US'), [])
eq('option of an unlisted value', enumOption(ipv4Type, 'wifi', 'en-US'), { value: 'wifi', label: 'wifi' })
eq('options of tags use the items', enumOptions({ ...tagsOneOf, items: { ...tagsOneOf.items, 'x-rackbook-enum-icons': { lan: 'network' } } }, 'zh-CN').map((o) => [o.value, o.label, o.icon]), [['public', '公网', undefined], ['lan', '局域网', 'network']])
eq('enum-like', [isEnumLike(ipv4Type), isEnumLike({ type: 'string', enum: ['a'] }), isEnumLike(tagsOneOf), isEnumLike({ type: 'string' })], [true, true, true, false])
eq('title en-US', fieldTitle(ipv4Type, 'ipv4_type', 'en-US'), 'IPv4 type')
eq('title zh-CN standard', fieldTitle(ipv4Type, 'ipv4_type', 'zh-CN'), 'IPv4 类型')
eq('title falls back to the field name', fieldTitle({ type: 'string' }, 'os', 'en-US'), 'os')
eq('description en-US', fieldDescription(ipv4Type, 'en-US'), 'How the address is assigned')
eq('description zh-TW falls back', fieldDescription(ipv4Type, 'zh-TW'), '地址的分配方式')
eq('no description', fieldDescription({ type: 'string' }, 'en-US'), undefined)

// a typed label stands for its code, in any language
eq('typed code', codeForLabel(ipv4Type, 'static'), 'static')
eq('typed zh label', codeForLabel(ipv4Type, '静态'), 'static')
eq('typed en label', codeForLabel(ipv4Type, 'Static'), 'static')
eq('typed zh-TW label', codeForLabel(ipv4Type, '靜態'), 'static')
eq('typed label ignoring case', codeForLabel(ipv4Type, 'DYNAMIC'), 'dynamic')
eq('typed label with spaces', codeForLabel(ipv4Type, '  动态 '), 'dynamic')
eq('typed unknown', codeForLabel(ipv4Type, 'wifi'), undefined)
eq('typed empty', codeForLabel(ipv4Type, ''), undefined)
eq('typed on a non-enum', codeForLabel({ type: 'string' }, 'x'), undefined)
const clash = { type: 'string', oneOf: [{ const: 'a', title: 'Same' }, { const: 'b', title: 'same' }, { const: 'c' }] }
eq('typed label exact match wins over case-insensitive', codeForLabel(clash, 'Same'), 'a')
eq('typed label ambiguous ignoring case', codeForLabel(clash, 'SAME'), undefined)
eq('typed code wins', codeForLabel({ type: 'string', oneOf: [{ const: 'x', title: 'y' }, { const: 'y', title: 'x' }] }, 'x'), 'x')
eq('search by label in another language', enumMatches(ipv4Type, 'static', 'Stat'), true)
eq('search by code', enumMatches(ipv4Type, 'static', 'STAT'), true)
eq('search by the standard text', enumMatches(ipv4Type, 'static', '静'), true)
eq('search miss', enumMatches(ipv4Type, 'static', 'dyn'), false)
eq('search empty', enumMatches(ipv4Type, 'static', ' '), true)

// meta objects
const coll = { name: 'devices', title: '设备', description: '所有设备', group: '网段规划', i18n: { 'en-US': { title: 'Devices', group: 'Network plans' } } }
eq('collection title en-US', collectionTitle(coll, 'en-US'), 'Devices')
eq('collection title zh-TW falls back', collectionTitle(coll, 'zh-TW'), '设备')
eq('collection description falls back', collectionDescription(coll, 'en-US'), '所有设备')
eq('collection group en-US', collectionGroup(coll, 'en-US'), 'Network plans')
eq('collection group none', collectionGroup({ name: 'x', title: 'X' }, 'en-US'), undefined)
eq('collection title falls back to the name', collectionTitle({ name: 'x', title: '' }, 'en-US'), 'x')
eq('ledger title', [ledgerTitle({ title: '台账', i18n: { 'en-US': { title: 'Ledger' } } }, 'en-US'), ledgerTitle({ title: '台账' }, 'en-US')], ['Ledger', '台账'])
eq('note title', [noteTitle({ title: '规则', i18n: { 'en-US': { title: 'Rule' } } }, 'en-US'), noteTitle({ title: '规则' }, 'zh-TW')], ['Rule', '规则'])
eq('backref title', [backrefTitle({ title: '服务', i18n: { 'en-US': { title: 'Services' } } }, 'en-US'), backrefTitle({}, 'en-US')], ['Services', undefined])

// type editor: a draft read from /api/types/{name} keeps the default language (zh-CN) in the
// standard fields and the others under i18n; the header and the field list show the reader's.
const draft = {
  name: 'devices',
  title: '设备',
  i18n: { 'en-US': { title: 'Devices' }, 'zh-TW': { title: '' } },
  fields: [
    { name: 'name', title: '设备名', i18n: { 'en-US': { title: 'Device name' }, 'zh-TW': { title: '' } } },
    { name: 'os', title: '操作系统' },
    { name: 'notes' },
  ],
  ref: { backrefTitle: '地址', i18n: { 'en-US': { backref_title: 'Addresses' }, 'zh-TW': { backref_title: '' } } },
  enum: { value: 'router', label: '路由器', labels: { 'en-US': 'Router', 'zh-TW': '' } },
}
eq('type editor header en-US', collectionTitle(draft, 'en-US'), 'Devices')
eq('type editor header: empty translation falls back', collectionTitle(draft, 'zh-TW'), '设备')
eq('type editor header: no title shows the name', collectionTitle({ ...draft, title: '', i18n: undefined }, 'en-US'), 'devices')
eq('type editor field list en-US', draft.fields.map((f) => fieldDefTitle(f, 'en-US')), ['Device name', '操作系统', undefined])
eq('type editor field list: empty translation falls back', fieldDefTitle(draft.fields[0], 'zh-TW'), '设备名')
eq('type editor field list zh-CN', draft.fields.map((f) => fieldDefTitle(f, 'zh-CN')), ['设备名', '操作系统', undefined])
eq('type editor backref title', [refBackrefTitle(draft.ref, 'en-US'), refBackrefTitle(draft.ref, 'zh-TW'), refBackrefTitle({}, 'en-US')], ['Addresses', '地址', undefined])
eq('type editor enum label', [enumItemLabel(draft.enum, 'en-US'), enumItemLabel(draft.enum, 'zh-TW'), enumItemLabel({}, 'en-US')], ['Router', '路由器', undefined])

// placeholders and countries as shown
eq('tbd reads as the placeholder word', displayText({ type: 'string' }, 'tbd'), '待补')
eq('tbd in a list', displayText({ type: 'array', items: { type: 'string' } }, ['tbd', 'x']), '待补, x')
eq('enum value reads as its label', displayText(ipv4Type, 'static', 'en-US'), 'Static')
eq('unknown enum value as it is', displayText(ipv4Type, 'wifi', 'en-US'), 'wifi')
eq('tags read as labels', displayText(tagsOneOf, ['public', 'lan'], 'zh-CN'), '公网, 局域网')
const tagsParent = { ...tagsOneOf, 'x-rackbook-i18n': { 'en-US': { enum: { public: 'Public' } } } }
eq('array labels: translation on the parent array', displayText(tagsParent, ['public', 'lan'], 'en-US'), 'Public, 局域网')
eq('array labels agree with the options', enumOptions(tagsParent, 'en-US').map((o) => o.label), ['Public', '局域网'])
eq('country as plain text has no flag', displayText({ type: 'string', format: 'country' }, 'US', 'en-US'), 'United States')
const byName = [{ f: 'JP' }, { f: 'AU' }, { f: 'US' }].sort((a, b) => countryName(a.f, 'en-US').localeCompare(countryName(b.f, 'en-US'))).map((x) => x.f)
eq('country sorts by the shown name, not the flag', byName, ['AU', 'JP', 'US'])
eq('country list is sorted by name in plain text', ['JP', 'AU'].map((c) => displayText({ type: 'string', format: 'country' }, c, 'en-US')).sort(), ['Australia', 'Japan'])
eq('subdivision as plain text is the code', displayText({ type: 'string', format: 'subdivision' }, 'US-OR', 'en-US'), 'US-OR')
eq('country tbd', displayText({ type: 'string', format: 'country' }, 'tbd'), '待补')
eq('plain text as written', displayText({ type: 'string' }, '静态'), '静态')
eq('flag', [flagEmoji('CN'), flagEmoji('cn'), flagEmoji('USA'), flagEmoji('')], ['🇨🇳', '', '', ''])
eq('country name zh-CN', countryName('CN', 'zh-CN'), '中国')
eq('country name en-US', countryName('TW', 'en-US'), 'Taiwan')
eq('country name of a non-code', countryName('tbd', 'en-US'), 'tbd')
eq('subdivision country', [subdivisionCountry('US-OR'), subdivisionCountry('tbd'), subdivisionCountry('us-or')], ['US', undefined, undefined])
eq('country list', [COUNTRY_CODES.length, COUNTRY_CODES.includes('US'), COUNTRY_CODES.includes('XK'), COUNTRY_CODES.includes('UK'), [...COUNTRY_CODES].sort().join() === COUNTRY_CODES.join()], [249, true, false, false, true])
for (const c of COUNTRY_CODES) if (countryName(c, 'en-US') === c) eq('country has a name ' + c, countryName(c, 'en-US'), '(a name)')

// icon names: only real lucide icons have a loader
import lucideLoaders from 'lucide-react/dynamicIconImports'
import { iconLoader } from '../src/lib/iconTable.ts'
const loaders = lucideLoaders as never
eq('icon loader of a real icon', typeof iconLoader(loaders, 'circle-check'), 'function')
eq('icon loader of an alias', typeof iconLoader(loaders, 'circle-help'), 'function')
for (const n of ['icon', 'lucide-provider', 'create-lucide-icon', 'Icon', 'LucideProvider', 'createLucideIcon', 'icons', 'constructor', '__proto__', 'toString', 'nope', '']) {
  eq('icon loader rejects ' + JSON.stringify(n), iconLoader(loaders, n), undefined)
}
eq('icon loader without a table', iconLoader(null, 'circle-check'), undefined)

// error paths and the allowed values an enum error lists
const rootSchema = { type: 'object', properties: { ipv4_type: ipv4Type, exposure: tagsOneOf, ports: rowsOneOf } }
eq('propAt property', propAt(rootSchema, '.ipv4_type'), ipv4Type)
eq('propAt array item', propAt(rootSchema, '.exposure[0]'), tagsOneOf.items)
eq('propAt row property', (propAt(rootSchema, '.ports[2].protocol') as any)?.oneOf?.[0]?.const, 'tcp')
// the form RJSF 6 actually gives e.property: instancePath with "/" turned into "."
eq('propAt array item (RJSF path)', propAt(rootSchema, '.exposure.0'), tagsOneOf.items)
eq('propAt row property (RJSF path)', (propAt(rootSchema, '.ports.2.protocol') as any)?.oneOf?.[0]?.const, 'tcp')
eq('propAt unknown', propAt(rootSchema, '.nope.x'), undefined)
eq('allowed values with labels', enumChoices(ipv4Type, ['static', 'dynamic', 'nat'], 'zh-CN'), ['静态 (static)', '动态 (dynamic)', 'nat'])
eq('allowed values en-US', enumChoices(ipv4Type, ['static', 'nat'], 'en-US'), ['Static (static)', 'NAT (nat)'])
eq('allowed values of a plain enum', enumChoices({ type: 'string', enum: ['a'] }, ['a'], 'en-US'), ['a'])
eq('allowed values without a schema', enumChoices(undefined, ['a'], 'en-US'), ['a'])


// server issues in the current language (keyword + params), the English message as the fallback
{
  const devices = {
    name: 'devices',
    title: '设备',
    i18n: { 'en-US': { title: 'Devices' } },
    schema: { type: 'object', properties: { name: { type: 'string', title: '名称', 'x-rackbook-i18n': { 'en-US': { title: 'Name' } } }, ipv4_type: ipv4Type, owner: { type: 'string' } } },
  }
  const people = { name: 'people', title: '人员', schema: { type: 'object', properties: { name: { type: 'string', title: '姓名' } } } }
  const cols = [devices, people]
  const at = (keyword: string, params: Record<string, unknown>, path = '') => ({ collection: 'devices', path, message: 'english fallback', keyword, params })
  const cases: [string, ReturnType<typeof at>, Record<string, string>][] = [
    ['enum hint', at('enum', { value: '静态', use: 'static' }, '/ipv4_type'), { 'zh-CN': '不能填写“静态”，请改用代码 static（静态）', 'en-US': '"静态" is not allowed; use code static (Static)', 'zh-TW': '不能填寫「静态」，請改用代碼 static（靜態）' }],
    ['enum list', at('enum', { value: 'x', allowed: ['static', 'nat'] }, '/ipv4_type'), { 'zh-CN': '只能是：静态 (static)、nat', 'en-US': 'Must be one of: Static (static), NAT (nat)' }],
    ['required', at('required', { missing: ['name', 'zzz'] }), { 'zh-CN': '缺少必填字段：名称、zzz', 'en-US': 'Missing required fields: Name, zzz' }],
    ['unique key', at('unique', { fields: ['name'], values: ['gw'], key: true }), { 'zh-CN': '键重复：“gw”（名称）', 'en-US': 'Duplicate key "gw" (Name)' }],
    ['ref with rule message', at('ref', { value: 'bob', target: 'people.name', ruleMessage: '负责人不存在', ruleMessageI18n: { 'en-US': 'Unknown owner' } }, '/owner'), { 'zh-CN': '负责人不存在：人员 · 姓名 中没有“bob”', 'en-US': 'Unknown owner: "bob" is not in 人员 · 姓名', 'zh-TW': '负责人不存在：人员 · 姓名 中沒有「bob」' }],
    ['ref without rule message', at('ref', { value: 'bob', target: 'nowhere.x' }, '/owner'), { 'en-US': '"bob" is not in nowhere.x' }],
    ['same_set right side', at('same_set', { value: 'v', side: 'right', left: 'devices.name', right: 'x.yml /a' }), { 'en-US': 'Devices · Name must equal x.yml /a: "v" in x.yml /a has no matching record' }],
    ['format', at('format', { value: 'XX', format: 'country' }, '/c'), { 'en-US': 'Not a valid country code (ISO 3166-1, such as US or CN, or tbd)' }],
    ['minimum', at('minimum', { limit: 1000.5, value: 1 }, '/n'), { 'en-US': 'Out of range (must be ≥ 1,000.5)', 'zh-CN': '超出范围（≥ 1,000.5）' }],
    ['unknown keyword', at('if', {}), { 'en-US': 'english fallback', 'zh-CN': 'english fallback' }],
    ['missing params', at('required', {}), { 'en-US': 'english fallback' }],
    ['no keyword', { collection: 'devices', message: 'english fallback' } as any, { 'zh-TW': 'english fallback' }],
  ]
  for (const loc of ['zh-CN', 'en-US', 'zh-TW'] as const) {
    await activateLocale(loc)
    for (const [name, issue, want] of cases) if (want[loc] !== undefined) eq(`issue ${name} (${loc})`, issueText(issue, cols), want[loc])
  }
  await activateLocale('zh-CN')
}
// version diffs: how values are shown, and what a refused restore leads to
eq('value text string', valueText('a b'), 'a b')
eq('value text number', valueText(0), '0')
eq('value text false', valueText(false), 'false')
eq('value text list', valueText([1, { a: 'x' }]), '[1,{"a":"x"}]')
eq('value text null', valueText(null), '')
eq('long: short one line', isLongValue('abc'), false)
eq('long: many characters', isLongValue('x'.repeat(161)), true)
eq('long: many lines', isLongValue('a\nb\nc\nd'), true)
eq('short value cuts lines', shortValue('a\nb\nc\nd\ne'), 'a\nb\nc…')
eq('short value cuts characters', shortValue('测'.repeat(200)), '测'.repeat(160) + '…')
eq('short value of a short one', shortValue('ab'), 'ab')
eq('short hash', shortHash('0123456789abcdef'), '0123456')
eq('restore: secret', restoreStep({ statusCode: 422, code: 'secret_suspected' }), 'secret')
eq('restore: edit', restoreStep({ statusCode: 409, code: 'restore_needs_edit' }), 'edit')
eq('restore: conflict', restoreStep({ statusCode: 409, code: 'conflict' }), 'conflict')
eq('restore: unchanged', restoreStep({ statusCode: 409, code: 'already_current' }), 'unchanged')
eq('restore: refused', restoreStep({ statusCode: 403, code: 'forbidden' }), 'refused')
eq('restore: a block-tier secret is a failure', restoreStep({ statusCode: 422, code: 'secret_detected' }), 'failed')
eq('restore: not found', restoreStep({ statusCode: 404, code: 'not_found' }), 'failed')
// values an old version hid: where they were, and what still needs a decision
eq('pointer', pointerSegments('/ports/1/a~1b'), ['ports', '1', 'a/b'])
eq('pointer of the record', pointerSegments(''), [])
const hcur = { name: 'x', ports: [{ proto: 'tcp' }, { proto: 'udp', key: 'k' }], token: 'now' }
eq('get at path', getAtPath(hcur, ['ports', '1', 'key']), 'k')
eq('get at a missing path', getAtPath(hcur, ['ports', '5', 'key']), undefined)
eq('set a field', setAtPath(hcur, ['token'], 'new').token, 'new')
eq('set leaves the original alone', hcur.token, 'now')
eq('remove a field', Object.keys(setAtPath(hcur, ['token'], undefined)).includes('token'), false)
eq('set a nested field', (setAtPath(hcur, ['ports', '1', 'key'], 'z') as typeof hcur).ports[1].key, 'z')
eq('remove a list element leaves the others in place', (setAtPath(hcur, ['ports', '0'], undefined) as typeof hcur).ports.length, 2)
const hdraft = { name: 'x', ports: [{ proto: 'tcp' }, { proto: '' }] }
eq('nothing entered: both need a decision', unresolvedHidden(['/token', '/ports/1/proto'], {}, hdraft, hdraft), ['/token', '/ports/1/proto'])
eq('entered a value', unresolvedHidden(['/token', '/ports/1/proto'], {}, { ...hdraft, token: 'typed' }, hdraft), ['/ports/1/proto'])
eq('chose', unresolvedHidden(['/token', '/ports/1/proto'], { '/token': 'keep', '/ports/1/proto': 'empty' }, hdraft, hdraft), [])
eq('typed and cleared again is not a decision', unresolvedHidden(['/token'], {}, { ...hdraft, token: undefined }, hdraft), ['/token'])

// audit events as sentences: a role change (and why it was seen), and a sign-in whose claims were cut off
{
  const changed = { time: '', area: 'audit', kind: 'role_changed', from: 'editor', to: 'viewer', auditor_from: false, auditor_to: false, cause: 'config' } as const
  const cases: [string, Parameters<typeof eventSentence>[0], Record<string, string>][] = [
    ['role changed after a config change', changed, { 'en-US': 'role changed from Editor to Viewer (after a rackbook.yml change)', 'zh-CN': '角色由「编辑」变为「只读」（rackbook.yml 修改后）', 'zh-TW': '角色由「編輯」變更為「唯讀」（rackbook.yml 變更後）' }],
    ['role changed at sign-in, now an auditor', { ...changed, to: 'admin', auditor_to: true, cause: 'sign_in' }, { 'en-US': 'role changed from Editor to Admin, now an auditor (seen at sign-in)', 'zh-CN': '角色由「编辑」变为「管理员」，并成为审计员（登录时发现）', 'zh-TW': '角色由「編輯」變更為「管理員」，並成為稽核員（登入時發現）' }],
    ['auditor flag only', { ...changed, to: 'editor', auditor_from: true }, { 'en-US': 'role unchanged (Editor), no longer an auditor (after a rackbook.yml change)', 'zh-CN': '角色不变（编辑），不再是审计员（rackbook.yml 修改后）', 'zh-TW': '角色不變（編輯），不再是稽核員（rackbook.yml 變更後）' }],
    ['role lost', { ...changed, to: 'none', cause: 'sign_in' }, { 'en-US': 'role changed from Editor to No access (seen at sign-in)' }],
    ['unknown cause', { ...changed, cause: 'whatever' }, { 'en-US': 'role changed from Editor to Viewer (whatever)' }],
    ['sign-in with groups cut off', { time: '', area: 'audit', kind: 'login', role: 'viewer', method: 'oidc', groups: 'overage' }, { 'en-US': 'signed in as Viewer (Single sign-on (OIDC)): the identity provider sent too many groups; the ones past the limit were not used' }],
    ['sign-in with both cut off', { time: '', area: 'audit', kind: 'login', role: 'viewer', method: 'oidc', groups: 'overage', app_roles: 'overage' }, { 'en-US': 'signed in as Viewer (Single sign-on (OIDC)): the identity provider sent too many groups; the ones past the limit were not used; the identity provider sent too many app roles; the ones past the limit were not used' }],
    ['plain sign-in is unchanged', { time: '', area: 'audit', kind: 'login', role: 'viewer', method: 'oidc' }, { 'en-US': 'signed in as Viewer (Single sign-on (OIDC))' }],
  ]
  for (const loc of ['zh-CN', 'en-US', 'zh-TW'] as const) {
    await activateLocale(loc)
    for (const [name, item, want] of cases) if (want[loc] !== undefined) eq(`event ${name} (${loc})`, eventSentence(item as Parameters<typeof eventSentence>[0]), want[loc])
  }
  await activateLocale('zh-CN')
}

if (failed) process.exit(1)
console.log('console logic: ok')
