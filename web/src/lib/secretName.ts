// Field names that mark their value as a secret. Mirrors secretName in
// internal/secretscan/rules.go (keep the two in step): the console never offers
// the values already used in such a field as suggestions. Import-free so
// scripts/check-console-logic.mts can test it.

const FOLDED = /[\u200b-\u200f\u00ad\u2060-\u2064\ufeff]/g

// the case-insensitive part of the server's rule
const INSENSITIVE =
  /(?:password|passwd|passphrase|secrets?|tokens?)s?$|(?:^|[^a-z])(?:pwd|pass|api[_ -]?keys?|apikey|private[_ -]?keys?|privkey|psk|pre[_-]?shared[_-]?keys?|wpa[_ -]?passphrase|secret[_ -]?(?:access[_ -]?)?keys?|encryption[_ -]?keys?|signing[_ -]?keys?)$|(?:密码|密碼|口令|密钥|令牌|秘钥|凭据|凭证|授权码|私钥|访问密钥|パスワード|비밀번호|암호|패스워드)$/i
// the case-sensitive part (camelCase names)
const SENSITIVE = /(?:^|[A-Za-z0-9_ -])(?:ApiKey|PrivateKey|SecretKey|EncryptionKey|SigningKey|Psk|Pwd|Pass)s?$/

export function isSecretName(name: string): boolean {
  const n = name.replace(FOLDED, '').normalize('NFKC')
  return INSENSITIVE.test(n) || SENSITIVE.test(n)
}
