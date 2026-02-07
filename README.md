# steam-client-crypto

[![npm version](https://img.shields.io/npm/v/@steamlab/steam-crypto.svg)](https://www.npmjs.com/package/@steamlab/steam-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A TypeScript/Node.js library implementing Steam's cryptographic protocols for client connections. Provides encryption, decryption, and authentication primitives used in Steam's network protocol.

## Features

- **Session Key Generation** - Generate and encrypt symmetric session keys with Steam's public RSA key
- **AES Encryption/Decryption** - Encrypt and decrypt Steam protocol payloads using AES-256-CBC with HMAC-based IV
- **CRC32 Checksum** - Compute CRC32 checksums for data integrity verification
- **RSA Password Encryption** - Encrypt passwords with Steam's RSA public keys for authentication
- **Dual ESM/CJS Support** - Works with both ES modules and CommonJS
- **Type-Safe** - Full TypeScript support with comprehensive type definitions
- **Zero Dependencies** - Uses only Node.js built-in crypto module

## Installation

```bash
npm install @steamlab/steam-crypto
```

**Requirements:**
- Node.js >= 20.0.0
- npm >= 9.5.1

## Usage

### Basic Example

```typescript
import SteamCrypto from "@steamlab/steam-crypto";

// Generate session key for Steam connection
const nonce = Buffer.from("your-nonce-from-steam", "hex");
const sessionKey = SteamCrypto.genSessionKey(nonce);

// Encrypt data to send to Steam
const message = Buffer.from("Hello, Steam!");
const encrypted = SteamCrypto.encrypt(message, sessionKey.plain);

// Decrypt data received from Steam
const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

// Compute CRC32 checksum
const checksum = SteamCrypto.crc32(Buffer.from("data"));

// Encrypt password for authentication
const encryptedPassword = SteamCrypto.rsaEncrypt(
  "myPassword123",
  "publicKeyModulus",
  "publicKeyExponent"
);
```

### CommonJS

```javascript
const SteamCrypto = require("@steamlab/steam-crypto").default;

const nonce = Buffer.alloc(16);
const sessionKey = SteamCrypto.genSessionKey(nonce);
console.log("Session key generated:", sessionKey.plain.length, "bytes");
```

## API Reference

### `SteamCrypto`

Abstract class providing static methods for Steam cryptographic operations.

#### `genSessionKey(nonce: Buffer): SessionKey`

Generates a 32-byte symmetric AES session key and encrypts it with Steam's public RSA "System" key.

**Parameters:**
- `nonce` - 16-byte nonce obtained from Steam's `channelEncryptResponse` message

**Returns:** `SessionKey` object with:
- `plain` - 32-byte Buffer containing the unencrypted session key
- `encrypted` - 128-byte Buffer containing the RSA-encrypted session key

**Example:**
```typescript
const nonce = Buffer.from("1234567890abcdef", "hex");
const { plain, encrypted } = SteamCrypto.genSessionKey(nonce);
// Use 'encrypted' to send to Steam
// Use 'plain' for subsequent encryption/decryption
```

---

#### `encrypt(data: Buffer, key: Buffer): Buffer`

Encrypts data using AES-256-CBC with an HMAC-SHA1 based IV for transmission to Steam.

**Parameters:**
- `data` - Buffer containing the data to encrypt
- `key` - 32-byte session key (from `sessionKey.plain`)

**Returns:** Buffer containing encrypted IV (16 bytes) + encrypted data

**Example:**
```typescript
const sessionKey = SteamCrypto.genSessionKey(nonce);
const payload = Buffer.from(protobufData);
const encrypted = SteamCrypto.encrypt(payload, sessionKey.plain);
```

---

#### `decrypt(data: Buffer, key: Buffer): Buffer`

Decrypts data received from Steam that was encrypted with AES-256-CBC.

**Parameters:**
- `data` - Buffer containing encrypted IV + encrypted data
- `key` - 32-byte session key (from `sessionKey.plain`)

**Returns:** Buffer containing decrypted plaintext data

**Example:**
```typescript
const sessionKey = SteamCrypto.genSessionKey(nonce);
const received = Buffer.from(steamResponse);
const decrypted = SteamCrypto.decrypt(received, sessionKey.plain);
```

---

#### `crc32(buffer: Buffer): number`

Computes CRC32 checksum of the given buffer as an unsigned 32-bit integer.

**Parameters:**
- `buffer` - Buffer to compute checksum for

**Returns:** Unsigned 32-bit integer CRC32 checksum

**Example:**
```typescript
const data = Buffer.from("Hello, World!");
const checksum = SteamCrypto.crc32(data);
console.log(`CRC32: 0x${checksum.toString(16)}`);

// Verify known value
const test = SteamCrypto.crc32(Buffer.from("123456789"));
console.log(test === 0xcbf43926); // true
```

---

#### `rsaEncrypt(password: string, publicKeyMod: string, publicKeyExp: string): string`

Encrypts a password using RSA public key encryption with PKCS1 padding.

**Parameters:**
- `password` - Password string to encrypt
- `publicKeyMod` - RSA public key modulus as hex string (from Steam)
- `publicKeyExp` - RSA public key exponent as hex string (from Steam)

**Returns:** Base64-encoded encrypted password

**Example:**
```typescript
// Values obtained from Steam's GetPasswordRSAPublicKey API
const modulus = "a1b2c3d4..."; // hex string
const exponent = "010001"; // hex string (typically 65537)

const encryptedPassword = SteamCrypto.rsaEncrypt(
  "mySecurePassword",
  modulus,
  exponent
);

// Send encryptedPassword to Steam for authentication
```

---

### Types

#### `SessionKey`

```typescript
interface SessionKey {
  plain: Buffer;      // 32-byte unencrypted session key
  encrypted: Buffer;  // 128-byte RSA-encrypted session key
}
```

## Used In

This library is used by [@steamlab/steam-client](https://github.com/fcastrocs/steam-client) for Steam network protocol implementation.

## License

MIT

## Links

- [GitHub Repository](https://github.com/fcastrocs/steam-client-crypto)
- [npm Package](https://www.npmjs.com/package/@steamlab/steam-crypto)
- [Steam Client](https://github.com/fcastrocs/steam-client) - Parent project using this library
