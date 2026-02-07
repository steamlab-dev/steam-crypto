import { beforeEach, describe, expect, it } from "vitest";
import SteamCrypto, { type SessionKey } from "../src/index";

describe("SteamCrypto", () => {
  describe("genSessionKey", () => {
    it("should generate a session key with plain and encrypted buffers", () => {
      const nonce = Buffer.alloc(16);
      const sessionKey = SteamCrypto.genSessionKey(nonce);

      expect(sessionKey).toHaveProperty("plain");
      expect(sessionKey).toHaveProperty("encrypted");
      expect(Buffer.isBuffer(sessionKey.plain)).toBe(true);
      expect(Buffer.isBuffer(sessionKey.encrypted)).toBe(true);
    });

    it("should generate a 32-byte plain session key", () => {
      const nonce = Buffer.alloc(16);
      const sessionKey = SteamCrypto.genSessionKey(nonce);

      expect(sessionKey.plain.length).toBe(32);
    });

    it("should generate encrypted session key with valid length", () => {
      const nonce = Buffer.alloc(16);
      const sessionKey = SteamCrypto.genSessionKey(nonce);

      // RSA encrypted data should be 128 bytes (1024-bit key)
      expect(sessionKey.encrypted.length).toBe(128);
    });

    it("should generate different keys on each call", () => {
      const nonce = Buffer.alloc(16);
      const sessionKey1 = SteamCrypto.genSessionKey(nonce);
      const sessionKey2 = SteamCrypto.genSessionKey(nonce);

      expect(sessionKey1.plain.equals(sessionKey2.plain)).toBe(false);
      expect(sessionKey1.encrypted.equals(sessionKey2.encrypted)).toBe(false);
    });

    it("should work with different nonce values", () => {
      const nonce1 = Buffer.from("0123456789abcdef", "hex");
      const nonce2 = Buffer.from("fedcba9876543210", "hex");

      const sessionKey1 = SteamCrypto.genSessionKey(nonce1);
      const sessionKey2 = SteamCrypto.genSessionKey(nonce2);

      expect(sessionKey1.plain.length).toBe(32);
      expect(sessionKey2.plain.length).toBe(32);
      expect(sessionKey1.encrypted.length).toBe(128);
      expect(sessionKey2.encrypted.length).toBe(128);
    });
  });

  describe("encrypt and decrypt", () => {
    let sessionKey: SessionKey;

    beforeEach(() => {
      const nonce = Buffer.alloc(16);
      sessionKey = SteamCrypto.genSessionKey(nonce);
    });

    it("should encrypt and decrypt data correctly", () => {
      const originalData = Buffer.from("Hello, Steam!");
      const encrypted = SteamCrypto.encrypt(originalData, sessionKey.plain);
      const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

      expect(decrypted.equals(originalData)).toBe(true);
    });

    it("should handle empty buffers", () => {
      const originalData = Buffer.alloc(0);
      const encrypted = SteamCrypto.encrypt(originalData, sessionKey.plain);
      const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

      expect(decrypted.equals(originalData)).toBe(true);
    });

    it("should handle large data", () => {
      const originalData = Buffer.alloc(10000, "a");
      const encrypted = SteamCrypto.encrypt(originalData, sessionKey.plain);
      const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

      expect(decrypted.equals(originalData)).toBe(true);
    });

    it("should produce different encrypted output for same data (due to random IV)", () => {
      const originalData = Buffer.from("Same data");
      const encrypted1 = SteamCrypto.encrypt(originalData, sessionKey.plain);
      const encrypted2 = SteamCrypto.encrypt(originalData, sessionKey.plain);

      // Should be different because IV is random
      expect(encrypted1.equals(encrypted2)).toBe(false);

      // But both should decrypt to the same original data
      const decrypted1 = SteamCrypto.decrypt(encrypted1, sessionKey.plain);
      const decrypted2 = SteamCrypto.decrypt(encrypted2, sessionKey.plain);

      expect(decrypted1.equals(originalData)).toBe(true);
      expect(decrypted2.equals(originalData)).toBe(true);
    });

    it("should handle binary data correctly", () => {
      const originalData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      const encrypted = SteamCrypto.encrypt(originalData, sessionKey.plain);
      const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

      expect(decrypted.equals(originalData)).toBe(true);
    });

    it("should include encrypted IV in output (first 16 bytes)", () => {
      const originalData = Buffer.from("Test data");
      const encrypted = SteamCrypto.encrypt(originalData, sessionKey.plain);

      // Encrypted output should include 16 bytes of encrypted IV + encrypted data
      expect(encrypted.length).toBeGreaterThan(16);
    });

    it("should handle unicode strings correctly", () => {
      const originalData = Buffer.from("Hello 世界 🌍", "utf-8");
      const encrypted = SteamCrypto.encrypt(originalData, sessionKey.plain);
      const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

      expect(decrypted.equals(originalData)).toBe(true);
      expect(decrypted.toString("utf-8")).toBe("Hello 世界 🌍");
    });
  });

  describe("crc32", () => {
    it("should compute CRC32 for empty buffer", () => {
      const buffer = Buffer.alloc(0);
      const crc = SteamCrypto.crc32(buffer);

      expect(typeof crc).toBe("number");
      expect(crc).toBe(0);
    });

    it("should compute CRC32 for known values", () => {
      // Known CRC32 value for "123456789" is 0xCBF43926
      const buffer = Buffer.from("123456789", "ascii");
      const crc = SteamCrypto.crc32(buffer);

      expect(crc).toBe(0xcbf43926);
    });

    it("should compute CRC32 for another known value", () => {
      // Known CRC32 value for "The quick brown fox jumps over the lazy dog" is 0x414FA339
      const buffer = Buffer.from("The quick brown fox jumps over the lazy dog", "ascii");
      const crc = SteamCrypto.crc32(buffer);

      expect(crc).toBe(0x414fa339);
    });

    it("should compute different CRC32 for different data", () => {
      const buffer1 = Buffer.from("test1");
      const buffer2 = Buffer.from("test2");

      const crc1 = SteamCrypto.crc32(buffer1);
      const crc2 = SteamCrypto.crc32(buffer2);

      expect(crc1).not.toBe(crc2);
    });

    it("should compute same CRC32 for identical data", () => {
      const buffer1 = Buffer.from("same data");
      const buffer2 = Buffer.from("same data");

      const crc1 = SteamCrypto.crc32(buffer1);
      const crc2 = SteamCrypto.crc32(buffer2);

      expect(crc1).toBe(crc2);
    });

    it("should return unsigned 32-bit integer", () => {
      const buffer = Buffer.from("test");
      const crc = SteamCrypto.crc32(buffer);

      expect(crc).toBeGreaterThanOrEqual(0);
      expect(crc).toBeLessThan(2 ** 32);
      expect(Number.isInteger(crc)).toBe(true);
    });

    it("should handle binary data correctly", () => {
      const buffer = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      const crc = SteamCrypto.crc32(buffer);

      expect(typeof crc).toBe("number");
      expect(crc).toBeGreaterThanOrEqual(0);
    });
  });

  describe("rsaEncrypt", () => {
    // Using test RSA keys (these are example values)
    // In real scenarios, these would be provided by Steam
    const testPublicKeyMod =
      "c1b05c17a86c7c6bb3eb87f0f52e0c3e5cb6607a0c5c4c2e5ef5f44b3f2c8d0e3c" +
      "1b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    const testPublicKeyExp = "010001"; // 65537 in hex

    it("should encrypt password and return base64 string", () => {
      const password = "testpassword123";
      const encrypted = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.length).toBeGreaterThan(0);
      // Should be valid base64
      expect(() => Buffer.from(encrypted, "base64")).not.toThrow();
    });

    it("should produce different encrypted values for same password (due to padding)", () => {
      const password = "samepassword";
      const encrypted1 = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);
      const encrypted2 = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);

      // RSA with PKCS1 padding includes random bytes, so outputs should differ
      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should handle empty password", () => {
      const password = "";
      const encrypted = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it("should handle moderately long passwords", () => {
      // RSA encryption has a size limit based on key size
      // For typical Steam keys, passwords under ~50 chars should work
      const password = "a".repeat(30);
      const encrypted = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it("should handle special characters in password", () => {
      const password = "p@ssw0rd!#$%^&*()";
      const encrypted = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.length).toBeGreaterThan(0);
    });

    it("should handle unicode characters in password", () => {
      const password = "密码🔐";
      const encrypted = SteamCrypto.rsaEncrypt(password, testPublicKeyMod, testPublicKeyExp);

      expect(typeof encrypted).toBe("string");
      expect(encrypted.length).toBeGreaterThan(0);
    });
  });

  describe("SessionKey interface", () => {
    it("should have correct structure", () => {
      const nonce = Buffer.alloc(16);
      const sessionKey = SteamCrypto.genSessionKey(nonce);

      expect(sessionKey).toHaveProperty("plain");
      expect(sessionKey).toHaveProperty("encrypted");
      expect(Object.keys(sessionKey).length).toBe(2);
    });
  });
});
