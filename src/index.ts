import { RSA_PKCS1_PADDING } from "node:constants";
import Crypto, { createPublicKey, publicEncrypt } from "node:crypto";

export interface SessionKey {
  plain: Buffer;
  encrypted: Buffer;
}

const SteamPublicKey = Buffer.from(`-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T
2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY
gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6
6WOiu4gZKODnFMBCiQIBEQ==
-----END PUBLIC KEY-----`);

const crc32Table = new Uint32Array(256).map((_, i) => {
  for (let j = 0; j < 8; j++) {
    i = i & 1 ? 0xedb88320 ^ (i >>> 1) : i >>> 1;
  }
  return i >>> 0;
});

export default abstract class SteamCrypto {
  /**
   * Generate a 32-byte symmetric sessionkey and encrypt it with Steam's public "System" key.
   * @param nonce - obtained in channelEncryptResponse when encrypting connection to Steam
   */
  static genSessionKey(nonce: Buffer): SessionKey {
    const sessionKey = Crypto.randomBytes(32);
    const encryptedSessionKey = Crypto.publicEncrypt(
      SteamPublicKey,
      Buffer.concat([sessionKey, nonce]),
    );
    return {
      plain: sessionKey,
      encrypted: encryptedSessionKey,
    };
  }

  /**
   * Encrypt data to be sent to Steam
   */
  static encrypt(data: Buffer, key: SessionKey["plain"]): Buffer {
    const IV = SteamCrypto.generateHmacIV(data, key);

    // Using AES-256-ECB for IV encryption
    const cipherIV = Crypto.createCipheriv("aes-256-ecb", key, null);
    cipherIV.setAutoPadding(false);
    const encryptedIV = cipherIV.update(IV);
    cipherIV.final();

    // Using AES-256-CBC for data encryption
    const cipherData = Crypto.createCipheriv("aes-256-cbc", key, IV);
    const encryptedData = Buffer.concat([cipherData.update(data), cipherData.final()]);

    // Return concatenated encrypted IV and data directly
    return Buffer.concat([encryptedIV, encryptedData]);
  }

  /**
   * Decrypt data received from Steam
   */
  static decrypt(data: Buffer, key: SessionKey["plain"]): Buffer {
    // Decipher IV (16 bytes)or online
    const decipherIV = Crypto.createDecipheriv("aes-256-ecb", key, null);
    decipherIV.setAutoPadding(false);
    const IV = decipherIV.update(data.subarray(0, 16));
    decipherIV.final();

    // Decipher data (rest of the buffer after the IV)
    const decipherData = Crypto.createDecipheriv("aes-256-cbc", key, IV);
    const decryptedData = Buffer.concat([
      decipherData.update(data.subarray(16)),
      decipherData.final(),
    ]);

    return decryptedData;
  }

  static crc32(buffer: Buffer): number {
    let crc = ~0;
    for (let i = 0; i < buffer.length; i++) {
      crc = crc32Table[(crc ^ buffer[i]!) & 0xff]! ^ (crc >>> 8);
    }
    return ~crc >>> 0;
  }

  /**
   * Encrypt password with RSA
   */
  static rsaEncrypt(password: string, publicKeyMod: string, publicKeyExp: string): string {
    // Create the public key from the modulus and exponent
    const publicKey = createPublicKey({
      key: {
        kty: "RSA",
        n: Buffer.from(publicKeyMod, "hex").toString("base64"),
        e: Buffer.from(publicKeyExp, "hex").toString("base64"),
      },
      format: "jwk",
    });

    // Encrypt the password using the public key
    return publicEncrypt(
      {
        key: publicKey,
        padding: RSA_PKCS1_PADDING,
      },
      Buffer.from(password),
    ).toString("base64");
  }

  /**
   * IV is [HMAC-SHA1(Random(3) + Plaintext) + Random(3)]. (Same random values for both)
   */
  private static generateHmacIV(data: Buffer, key: SessionKey["plain"]): Buffer {
    // 16 bytes of sessionkey
    const hmacSecret = key.subarray(0, 16);

    const random = Crypto.randomBytes(3);
    const hmac = Crypto.createHmac("sha1", hmacSecret);
    hmac.update(random);
    hmac.update(data);

    // IV must be 16 bytes long, slice 13 bytes and concat random at the end
    return Buffer.concat([hmac.digest().subarray(0, 13), random]);
  }
}
