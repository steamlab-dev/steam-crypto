import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import SteamCrypto from "@steamlab/steam-crypto";

async function runTests() {
  // Test 1: Package exports correctly
  if (typeof SteamCrypto !== "function") {
    console.error("❌ SteamCrypto is not exported correctly");
    process.exit(1);
  }

  // Test 2: Verify package.json metadata (discover from resolved entry)
  const entryPath = require.resolve("@steamlab/steam-crypto");
  let currentDir = dirname(entryPath);
  let pkgPath = resolve(currentDir, "package.json");
  while (!existsSync(pkgPath) && currentDir !== dirname(currentDir)) {
    currentDir = dirname(currentDir);
    pkgPath = resolve(currentDir, "package.json");
  }

  if (!existsSync(pkgPath)) {
    console.error("❌ package.json not found for installed package");
    process.exit(1);
  }

  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
    name?: string;
    version?: string;
    main?: string;
    types?: string;
  };
  if (!pkg.name || !pkg.version || !pkg.main || !pkg.types) {
    console.error("❌ Package metadata incomplete");
    process.exit(1);
  }
  console.log("✅ Package metadata valid");
  console.log("   - Name:", pkg.name);
  console.log("   - Version:", pkg.version);
  console.log("   - Main:", pkg.main);
  console.log("   - Types:", pkg.types);

  // Test 3: Check TypeScript types exist (use package.json path)
  const packagePath = dirname(pkgPath);
  const typesPath = resolve(packagePath, pkg.types);

  if (!existsSync(typesPath)) {
    console.error("❌ Type definitions not found at:", typesPath);
    process.exit(1);
  }

  // Test 4: Check for static methods
  try {
    const staticMethods = ["genSessionKey", "encrypt", "decrypt", "crc32", "rsaEncrypt"];
    const hasAllMethods = staticMethods.every((method) =>
      Object.getOwnPropertyNames(SteamCrypto).includes(method),
    );

    if (!hasAllMethods) {
      throw new Error(
        `Missing static methods. Available: ${Object.getOwnPropertyNames(SteamCrypto).join(", ")}`,
      );
    }
    console.log("✅ All static methods present");
  } catch (error) {
    console.error("❌ Failed to verify SteamCrypto methods:", error);
    process.exit(1);
  }

  // Test 5: Verify basic functionality
  try {
    const nonce = Buffer.alloc(16);
    const sessionKey = SteamCrypto.genSessionKey(nonce);

    if (!sessionKey.plain || !sessionKey.encrypted) {
      throw new Error("Session key missing required properties");
    }

    if (sessionKey.plain.length !== 32) {
      throw new Error(`Plain key should be 32 bytes, got ${sessionKey.plain.length}`);
    }

    if (sessionKey.encrypted.length !== 128) {
      throw new Error(`Encrypted key should be 128 bytes, got ${sessionKey.encrypted.length}`);
    }

    console.log("✅ genSessionKey works correctly");

    // Test encryption/decryption
    const testData = Buffer.from("test data");
    const encrypted = SteamCrypto.encrypt(testData, sessionKey.plain);
    const decrypted = SteamCrypto.decrypt(encrypted, sessionKey.plain);

    if (!testData.equals(decrypted)) {
      throw new Error("Encryption/decryption roundtrip failed");
    }

    console.log("✅ encrypt/decrypt work correctly");

    // Test CRC32
    const crc = SteamCrypto.crc32(Buffer.from("123456789"));
    if (crc !== 0xcbf43926) {
      throw new Error(`CRC32 incorrect. Expected 0xcbf43926, got 0x${crc.toString(16)}`);
    }

    console.log("✅ crc32 works correctly");

    // Test RSA encryption
    const testPubKeyMod =
      "c1b05c17a86c7c6bb3eb87f0f52e0c3e5cb6607a0c5c4c2e5ef5f44b3f2c8d0e3c" +
      "1b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    const testPubKeyExp = "010001";
    const encryptedPassword = SteamCrypto.rsaEncrypt("test", testPubKeyMod, testPubKeyExp);

    if (typeof encryptedPassword !== "string" || encryptedPassword.length === 0) {
      throw new Error("RSA encryption failed");
    }

    console.log("✅ rsaEncrypt works correctly");
  } catch (error) {
    console.error("❌ Functional tests failed:", error);
    process.exit(1);
  }
}

runTests();
