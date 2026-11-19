import { idFromPath, recordHref } from '../src/lib/recordUrl.ts'

let failed = 0
// Ids as the server builds them: "/" inside a key value is %2F, "%" is %25,
// and "/" between key fields is a plain separator.
for (const id of ['1Panel %2F aaPanel 面板', 'web-1/SSH', '50%25 of a%2Fb', 'all/NTP (UDP 123)', 'é ü #?&=+']) {
  for (const suffix of ['', '/edit']) {
    const href = recordHref('ports', id) + suffix
    const got = idFromPath(href)
    if (got !== id || href.split('/').length !== 4 + (suffix ? 1 : 0)) {
      console.error('FAIL', JSON.stringify(id), href, JSON.stringify(got))
      failed++
    }
  }
}
if (idFromPath('/c/ports') !== undefined || idFromPath('/c/ports/') !== undefined) {
  console.error('FAIL empty id')
  failed++
}
if (failed) process.exit(1)
console.log('record urls: ok')
