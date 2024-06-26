# Stedy (Beta)

> [!WARNING]\
> The security of this library has yet to be independently audited. Make your own
> judgement on whether or not the current state of this project is a good fit for
> you.

## Installation

```console
$ npm i --save stedy
```

## Basic usage

### Elliptic curve cryptography

#### Deriving shared secrets

Perform a key exchange using the X25519 Elliptic Curve Diffie-Hellman function.

```ts
import { diffieHellman, generateKeyPair } from 'stedy'

const alice = await generateKeyPair()
const bob = await generateKeyPair()
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

Create and verify Ed25519 signatures using the Edwards-curve Digital Signature
Algorithm.

```ts
import { sign, generateSignKeyPair, verify, fromString } from 'stedy'

const { privateKey, publicKey } = await generateSignKeyPair()
const message = fromString('Hello World')
const signature = await sign(message, privateKey)
const verified = await verify(message, publicKey, signature)
console.log(verified)
// true
```

### Secret key cryptography

Encrypt a message using AES in Galois/Counter Mode (GCM) with a 256-bit key.

```ts
import { decrypt, encrypt, generateKey, generateNonce, fromString } from 'stedy'

const message = fromString('Hello World')
const key = await generateKey()
const nonce = await generateNonce()
const ciphertext = await encrypt(key, nonce, message)
const decrypted = await decrypt(key, nonce, ciphertext)
console.log(decrypted.toString())
// Hello World
```

### Hash digests

Compute the SHA-512 digest of a given message.

```ts
import { hash, fromString } from 'stedy'

const message = fromString('Hello World')
const digest = await hash(message)
console.log(digest.toString('base64'))
// LHT9F+2v2A6ER7DUZ0HuJDt+t03SFJoKsbkkb7MDgvJ+hT2FhXGeDmfL2g2qj1FnEGRhXWRa4nrLFb+xRH9Fmw==
```

### Cryptographic HMAC digests

Generate a cryptographic HMAC hash using SHA-512.

```ts
import { hmac, fromString } from 'stedy'

const message = fromString('Hello World')
const key = fromString('secret')
const digest = await hmac(message, key)
console.log(digest.toString('base64'))
// CApRAydhlEam2xp19WEr2wM8jI66+E7uBbh/Z6VpvgmBACFtfVFX5VMtXh/e6lu75Tq5JAlI5jndeI4p19fk6w==
```

### HMAC-based Key Derivation Function (HKDF)

Derive a key using the HKDF algorithm with SHA-512.

```ts
import { hkdf, generateRandomBytes, fromString } from 'stedy'

const inputKey = fromString('secret')
const salt = await generateRandomBytes(64)
const info = fromString('my-app')
const outputKey = await hkdf(inputKey, salt, info)
console.log(outputKey.toString('base64'))
// AT0yteGs4wtCRyeP9i76mK20YMfhXlhWO2E83eWQ6YGmPXjWZ92XZX6KfXKXF2DUb1EvYcJ82qHTssQmrJdunw==
```

### Password-Based Key Derivation Function (PBKDF2)

Derive a key from a given password using PBKDF2 with SHA-512.

```ts
import { pbkdf2, generateRandomBytes, fromString } from 'stedy'

const password = fromString('horse-correct-battery-staple')
const salt = await generateRandomBytes(64)
const key = await pbkdf2(password, salt)
console.log(key.toString('base64'))
// xj4Rmi25dnoOX7Lf0zj/3bwE9PniTQsASu42bjZ96lEcwzo1UjCbTseifzDG6ShB4u1QRJUgFWlUYn6qfcf2XA==
```

## Advanced usage

### Elliptic curve cryptography

```ts
import { createCurve } from 'stedy'

const { diffieHellman, generateKeyPair, sign, generateSignKeyPair, verify } =
  createCurve('P-256', 'SHA-256')
```

### Secret key cryptography

```ts
import { createCipher } from 'stedy'

const { decrypt, encrypt, generateKey, generateNonce } =
  createCipher('AES-192-CBC')
```

### Hash-based functions

```ts
import { createHash } from 'stedy'

const { hash, hkdf, hmac, pbkdf2 } = createHash('SHA-384')
```
