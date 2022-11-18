# Stedy

## Installation

```console
$ npm i --save stedy
```

## Basic usage

### Elliptic curve cryptography

#### Deriving shared secrets

```ts
import { diffieHellman, keyPair } from 'stedy'
import { toString } from 'stedy/bytes'

const alice = await keyPair()
const bob = await keyPair()
const aliceSecret = await diffieHellman(alice.privateKey, bob.publicKey)
const bobSecret = await diffieHellman(bob.privateKey, alice.publicKey)
console.log({
  aliceSecret: aliceSecret.toString('base64'),
  bobSecret: bobSecret.toString('base64')
})
// {
//   aliceSecret: 'XJiXa0+XxscFfpud483+SQWdru48LNfZRxum2h4vEV8=',
//   bobSecret: 'XJiXa0+XxscFfpud483+SQWdru48LNfZRxum2h4vEV8='
// }
```

#### Verifying signatures

```ts
import { sign, signKeyPair, verify } from 'stedy'
import { fromString } from 'stedy/bytes'

const { privateKey, publicKey } = await signKeyPair()
const message = fromString('Hello World')
const signature = await sign(message, privateKey)
const verified = await verify(message, publicKey, signature)
console.log({ verified })
// { verified: true }
```

### Secret key cryptography

```ts
import { decrypt, encrypt, generateKey, randomBytes } from 'stedy'
import { fromString } from 'stedy/bytes'

const message = fromString('Hello World')
const key = await generateKey()
const nonce = await randomBytes(12)
const ciphertext = await encrypt(key, nonce, message)
const decrypted = await decrypt(key, nonce, ciphertext)
console.log(decrypted.toString())
// Hello World
```

### Hash digests

```ts
import { hash } from 'stedy'
import { fromString } from 'stedy/bytes'

const message = fromString('Hello World')
const digest = await hash(message)
console.log(digest.toString('base64'))
// LHT9F+2v2A6ER7DUZ0HuJDt+t03SFJoKsbkkb7MDgvJ+hT2FhXGeDmfL2g2qj1FnEGRhXWRa4nrLFb+xRH9Fmw==
```

### Cryptographic HMAC digests

```ts
import { hmac } from 'stedy'
import { fromString } from 'stedy/bytes'

const message = fromString('Hello World')
const key = fromString('secret')
const digest = await hmac(message, key)
console.log(digest.toString('base64'))
// CApRAydhlEam2xp19WEr2wM8jI66+E7uBbh/Z6VpvgmBACFtfVFX5VMtXh/e6lu75Tq5JAlI5jndeI4p19fk6w==
```

### HMAC Key Derivation Function (HKDF)

```ts
import { hkdf, randomBytes } from 'stedy'
import { fromString } from 'stedy/bytes'

const inputKey = fromString('secret')
const salt = await randomBytes(64)
const info = fromString('my-app')
const outputKey = await hkdf(inputKey, salt, info)
console.log(outputKey.toString('base64'))
// AT0yteGs4wtCRyeP9i76mK20YMfhXlhWO2E83eWQ6YGmPXjWZ92XZX6KfXKXF2DUb1EvYcJ82qHTssQmrJdunw==
```

### Password-Based Key Derivation Function (PBKDF2)

```ts
import { pbkdf2, randomBytes } from 'stedy'
import { fromString } from 'stedy/bytes'

const password = fromString('horse-correct-battery-staple')
const salt = await randomBytes(64)
const key = await pbkdf2(password, salt)
console.log(key.toString('base64'))
// xj4Rmi25dnoOX7Lf0zj/3bwE9PniTQsASu42bjZ96lEcwzo1UjCbTseifzDG6ShB4u1QRJUgFWlUYn6qfcf2XA==
```
