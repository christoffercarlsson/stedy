# Stedy

## Installation

```console
npm i --save stedy
```

## Basic usage

### Elliptic curve cryptography

#### Deriving shared secrets

```ts
import { diffieHellman, generateKeyPair } from 'stedy'
import { toString } from 'stedy/bytes'

const alice = await generateKeyPair()
const bob = await generateKeyPair()
const aliceSecret = await diffieHellman(alice.privateKey, bob.publicKey)
const bobSecret = await diffieHellman(bob.privateKey, alice.publicKey)
console.log({
  aliceSecret: toString(aliceSecret, 'hex'),
  bobSecret: toString(bobSecret, 'hex')
})
// {
//   aliceSecret: '0d570a1dcb741cf17a...16a8b2843b3c07aa56b4f2f',
//   bobSecret: '0d570a1dcb741cf17a...16a8b2843b3c07aa56b4f2f'
// }
```

#### Verifying signatures

```ts
import { sign, verify, generateSignKeyPair } from 'stedy'
import { fromString } from 'stedy/bytes'

const { privateKey, publicKey } = await generateSignKeyPair()
const message = fromString('Hello World')
const signature = await sign(message, privateKey)
const verified = await verify(message, publicKey, signature)
console.log({ verified })
// { verified: true }
```

### Secret key cryptography

```ts
import { decrypt, encrypt, generateKey, randomBytes } from 'stedy'
import { fromString, toString } from 'stedy/bytes'

const message = fromString('Hello World')
const key = await generateKey()
const nonce = await randomBytes(12)
const ciphertext = await encrypt(key, nonce, message)
const decrypted = await decrypt(key, nonce, ciphertext)
console.log({ decrypted: toString(decrypted) })
// { decrypted: 'Hello World' }
```

### Hash digests

```ts
import { hash } from 'stedy'
import { fromString, toString } from 'stedy/bytes'

const message = fromString('Hello World')
const digest = await hash(message)
console.log({ digest: toString(digest, 'hex') })
// { digest: '2c74fd17edafd80e8447b0d...fb1447f459b' }
```

### Cryptographic HMAC digests

```ts
import { hmac } from 'stedy'
import { fromString, toString } from 'stedy/bytes'

const message = fromString('Hello World')
const key = fromString('secret')
const digest = await hmac(message, key)
console.log({ digest: toString(digest, 'hex') })
// { digest: '080a510327619446...9d7d7e4eb' }
```

### HMAC Key Derivation Function (HKDF)

```ts
import { hkdf, randomBytes } from 'stedy'
import { fromString, toString } from 'stedy/bytes'

const inputKey = fromString('secret')
const salt = await randomBytes(64)
const info = fromString('my-app')
const outputKey = await hkdf(inputKey, salt, info)
console.log({ outputKey: toString(outputKey, 'hex') })
// { outputKey: '080a5103276...d7d7e4eb' }
```

### Password-Based Key Derivation Function (PBKDF2)

```ts
import { pbkdf2, randomBytes } from 'stedy'
import { fromString, toString } from 'stedy/bytes'

const password = fromString('horse-correct-battery-staple')
const salt = await randomBytes(64)
const key = await hkdf(pbkdf2, salt)
console.log({ key: toString(key, 'hex') })
// { key: '080a510327619...7e4eb' }
```
