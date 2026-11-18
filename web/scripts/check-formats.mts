import { customFormats as f } from '../src/lib/formats.ts'
const good: Record<string,string[]> = {
  ip: ["10.0.0.1","255.255.255.255","::1","2001:db8::1","fe80::1","::ffff:1.2.3.4"],
  ipv4: ["0.0.0.0","192.168.1.10","100.64.0.1"],
  ipv6: ["::","2001:db8:0:0:0:0:0:1","fd7a:115c:a1e0::1"],
  cidr: ["10.0.0.0/8","192.168.0.0/22","10.1.2.3/32","2001:db8::/32","::/0"],
  'port-spec': ["TCP 443","UDP 41641","tcp 22","TCP/UDP 53","TCP 8000-8010","TCP 80, 443","UDP 1-65535"],
  date: ["2026-01-31","2024-02-29","1999-12-31","0000-01-01","0000-02-29","0001-01-01","0099-12-31","0400-02-29"],
  textarea: ["","any\ntext"],
  hostname: ["a","example.com","web-1.dc.example.com","A1.b2","xn--bcher-kva.example"],
  uri: ["https://example.com","http://10.0.0.1:8080/x?y=1","ssh://git@host/repo","mailto:a@b.c","tel:+1555"],
}
const bad: Record<string,string[]> = {
  ip: ["","1.2.3","1.2.3.4.5","256.1.1.1","01.2.3.4","fe80::1%eth0","abc","10.0.0.1/24"],
  ipv4: ["::1","1.2.3","300.0.0.1"," 1.2.3.4","1.2.3.4 "],
  ipv6: ["1.2.3.4","2001:db8:::1","12345::1",":::"],
  cidr: ["10.0.0.0","10.0.0.0/33","10.0.0.0/-1","::1/129","10.0.0/8","/8","10.0.0.0/8/8"],
  'port-spec': ["443","TCP","TCP 0","TCP 65536","TCP 90-80","ICMP 1","TCP  443x","TCP 80,","TCP80","TCP 1-2-3"],
  date: ["0100-02-29","0001-02-29","0099-02-30","2026-02-30","2026-13-01","26-01-01","2026-1-1","2026/01/01","2026-01-01T00:00:00Z",""],
  hostname: ["","-a.com","a-.com","a..b","a_b.com","a b","a.com.","a".repeat(64)+".com"],
  uri: ["","example.com","//example.com","http://exa mple.com","1http://x","http:"],
}
let n = 0
for (const [k, v] of Object.entries(good)) for (const s of v) if (!f[k](s)) { console.log('SHOULD BE VALID', k, JSON.stringify(s)); n++ }
for (const [k, v] of Object.entries(bad)) for (const s of v) if (f[k](s)) { console.log('SHOULD BE INVALID', k, JSON.stringify(s)); n++ }
console.log('failures', n)
