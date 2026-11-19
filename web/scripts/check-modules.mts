import {
  addedExcludes,
  changedKeys,
  cleanSettings,
  countParts,
  defaultsToText,
  failedCount,
  firstBad,
  isAppId,
  isEmail,
  isRiskyChange,
  isTime,
  parseDefaults,
  parseThresholds,
  sameSettings,
  splitList,
  tone,
} from '../src/lib/modules.ts'

let failed = 0
function eq(name: string, got: unknown, want: unknown) {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error('FAIL', name, '\n  got ', JSON.stringify(got), '\n  want', JSON.stringify(want))
    failed++
  }
}

// times, ids, addresses
eq('times ok', ['00:00', '08:30', '23:59'].map(isTime), [true, true, true])
eq('times bad', ['8:00', '24:00', '12:60', '12:5', '', '08:00 '].map(isTime), [false, false, false, false, false, false])
eq('first bad time', firstBad(['08:00', '25:00', 'x'], isTime), '25:00')
eq('no bad time', firstBad(['08:00'], isTime), undefined)
eq('app id', [isAppId('11111111-2222-3333-4444-555555555555'), isAppId('AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee'), isAppId('nope'), isAppId('1111111-2222-3333-4444-555555555555')], [true, true, false, false])
eq('email', ['ops@example.org', 'a.b+c@x.example.com'].map(isEmail), [true, true])
eq('email bad', ['ops', 'a@b', 'A <a@b.co>', 'a@b.co, c@d.co', 'a b@c.de', ''].map(isEmail), [false, false, false, false, false, false])

// pasted lists
eq('split', splitList('a@x.org, b@x.org；c@x.org\n a@x.org'), ['a@x.org', 'b@x.org', 'c@x.org'])
eq('split empty', splitList(' , ; '), [])

// thresholds
eq('thresholds', parseThresholds(['7', '30', '7', '0']), { values: [30, 7, 0] })
eq('thresholds big', parseThresholds(['3650', '3651']), { values: [3650], error: '3651' })
eq('thresholds bad', parseThresholds(['7', 'x']), { values: [7], error: 'x' })
eq('thresholds negative', parseThresholds(['-1']), { values: [], error: '-1' })
eq('thresholds decimal', parseThresholds(['1.5']), { values: [], error: '1.5' })

// record defaults
eq('defaults empty', parseDefaults('  '), { value: undefined })
eq('defaults ok', parseDefaults('{"owner":"ops","used_by":["all"],"n":1,"b":true}').value, { owner: 'ops', used_by: ['all'], n: 1, b: true })
eq('defaults json', parseDefaults('{owner:'), { error: 'json' })
eq('defaults array', parseDefaults('[1]'), { error: 'object' })
eq('defaults null', parseDefaults('null'), { error: 'object' })
eq('defaults nested', parseDefaults('{"a":{"b":1}}'), { error: 'value' })
eq('defaults list of numbers', parseDefaults('{"a":[1]}'), { error: 'value' })
eq('defaults text', [defaultsToText(undefined), defaultsToText({}), defaultsToText({ a: 'b' })], ['', '', '{\n  "a": "b"\n}'])

// settings: what is stored and what changed
eq('clean drops empty', cleanSettings({ paused: false, send_at: [], timezone: '', thresholds: [30], recipients: ['a@b.co'], defaults: {} }), { recipients: ['a@b.co'], thresholds: [30] })
eq('clean keeps explicit false and empty prefix', cleanSettings({ service_principals: false, name_prefix: '' }), { name_prefix: '', service_principals: false })
eq('same ignores empties', sameSettings({ paused: false, language: '' }, {}), true)
eq('different', sameSettings({ language: 'zh' }, {}), false)
eq('changed keys', changedKeys({ language: 'zh', thresholds: [30, 7] }, { thresholds: [30, 7, 1], timezone: 'UTC' }), ['language', 'thresholds', 'timezone'])
eq('no changed keys', changedKeys({ paused: false }, {}), [])

// the change that asks first
const A = '11111111-2222-3333-4444-555555555555'
const B = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
eq('exclude one more is risky', isRiskyChange({ exclude_app_ids: [A] }, { exclude_app_ids: [A, B] }), true)
eq('exclude case-insensitive', addedExcludes({ exclude_app_ids: [A] }, { exclude_app_ids: [A.toUpperCase()] }), [])
eq('remove an exclusion is safe', isRiskyChange({ exclude_app_ids: [A, B] }, { exclude_app_ids: [A] }), false)
eq('service principals off is risky', isRiskyChange({}, { service_principals: false }), true)
eq('service principals already off', isRiskyChange({ service_principals: false }, { service_principals: false }), false)
eq('service principals on again is safe', isRiskyChange({ service_principals: false }, { service_principals: true }), false)
eq('other keys are safe', isRiskyChange({}, { sync_at: ['04:00'], timezone: 'UTC' }), false)

// badges
eq('tone failed beats paused', tone({ status: 'failed', paused: true }), 'failed')
eq('tone paused', tone({ status: 'ok', paused: true }), 'paused')
eq('tone ok', tone({ status: 'ok', paused: false }), 'ok')
eq('tone skipped', tone({ status: 'skipped', paused: false }), 'skipped')
eq('tone never', tone({ status: 'never', paused: false }), 'never')
eq('failed count', failedCount([{ status: 'failed' }, { status: 'ok' }, { status: 'failed' }, { status: 'never' }]), 2)

// counts by kind
const c = { created: 2, updated: 1, revoked: 0, sent: 5 }
eq('entra counts', countParts(c, 'entra'), [{ key: 'created', n: 2 }, { key: 'updated', n: 1 }, { key: 'revoked', n: 0 }])
eq('notify counts', countParts(c, 'notify'), [{ key: 'sent', n: 5 }])

if (failed) {
  console.error(`${failed} check(s) failed`)
  process.exit(1)
}
console.log('modules logic: ok')
