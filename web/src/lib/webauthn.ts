// WebAuthn glue: the server speaks go-webauthn's JSON (binary fields are
// base64url strings); the browser API wants ArrayBuffers.

const b64uToBuf = (s: string): ArrayBuffer => {
  const pad = '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

const bufToB64u = (b: ArrayBuffer | null): string => {
  if (!b) return ''
  let s = ''
  for (const byte of new Uint8Array(b)) s += String.fromCharCode(byte)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

type Descriptor = { id: string; type: PublicKeyCredentialType; transports?: AuthenticatorTransport[] }

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials
}

/** True when the user closed or refused the browser's passkey prompt. */
export function isCancelled(e: unknown): boolean {
  return e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')
}

export async function createCredential(options: { publicKey: Record<string, any> }): Promise<Record<string, unknown>> {
  const pk = options.publicKey
  const cred = (await navigator.credentials.create({
    publicKey: {
      ...pk,
      challenge: b64uToBuf(pk.challenge),
      user: { ...pk.user, id: b64uToBuf(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials ?? []).map((c: Descriptor) => ({ ...c, id: b64uToBuf(c.id) })),
    } as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null
  if (!cred) throw new DOMException('no credential', 'NotAllowedError')
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      attestationObject: bufToB64u(r.attestationObject),
      transports: r.getTransports?.() ?? [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
}

export async function getCredential(options: { publicKey: Record<string, any> }): Promise<Record<string, unknown>> {
  const pk = options.publicKey
  const cred = (await navigator.credentials.get({
    publicKey: {
      ...pk,
      challenge: b64uToBuf(pk.challenge),
      allowCredentials: (pk.allowCredentials ?? []).map((c: Descriptor) => ({ ...c, id: b64uToBuf(c.id) })),
    } as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null
  if (!cred) throw new DOMException('no credential', 'NotAllowedError')
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: bufToB64u(r.clientDataJSON),
      authenticatorData: bufToB64u(r.authenticatorData),
      signature: bufToB64u(r.signature),
      userHandle: r.userHandle ? bufToB64u(r.userHandle) : undefined,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
}
