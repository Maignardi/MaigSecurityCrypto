# Security Architecture & Threat Model

## 1. Key Hierarchy (Envelope Encryption)

`EncryptedDataStore` separates the **Key Encryption Key (KEK)** from the **Data Encryption Key (DEK)**:

- **Android (`androidMain`)**:
  - **KEK:** 256-bit AES-GCM key generated inside `AndroidKeyStore` (`setRandomizedEncryptionRequired(true)`).
    - Requests StrongBox (`SECURITY_LEVEL_STRONGBOX`) on API 28+ when `preferStrongBox = true` and `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is present.
    - Gracefully falls back to TEE hardware Keystore (`SECURITY_LEVEL_TRUSTED_ENVIRONMENT`) if StrongBox throws `StrongBoxUnavailableException` or `ProviderException`, emitting `SecurityEvent.StrongBoxFallbackToTee`.
    - All `AndroidKeyStore` calls are serialized via an internal synchronization lock to prevent OEM concurrency crashes.
  - **DEK:** Google Tink `KeysetHandle` (`AES256_GCM` or `XCHACHA20_POLY1305`) wrapped by the KEK using `TinkProtoKeysetFormat.serializeEncryptedKeyset` with domain-separated AAD (`packageName:storeName`), persisted atomically (`write -> flush -> fsync -> rename`) inside `noBackupFilesDir/encrypted_datastore/<storeName>.keyset` with `0600` permissions.
- **iOS (`iosMain`)**:
  - **DEK Keyset:** 256-bit CSPRNG (`SecRandomCopyBytes`) AES-GCM keys stored in the iOS Keychain (`kSecClassGenericPassword`) with `ThisDeviceOnly` accessibility (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` by default).
  - DataStore files are written inside `NSApplicationSupportDirectory/encrypted_datastore/` with `NSURLIsExcludedFromBackupKey = true` and `0700`/`0600` permissions.
- **JVM (`jvmMain`)**:
  - Uses Google Tink `KeysetHandle` wrapped with either a PBKDF2-HMAC-SHA256 key (`310,000` iterations, 32-byte CSPRNG salt) when `masterPassphraseProvider` is configured, or an isolated local AES-256-GCM KEK file (`0600`).

---

## 2. Authenticated Binary Envelope (`EDST` v1)

Every encrypted store payload uses a self-describing, authenticated binary framing:

| Offset | Length | Field | Notes |
| --- | --- | --- | --- |
| `0` | `4` | Magic | `"EDST"` (`0x45 0x44 0x53 0x54`) |
| `4` | `1` | Version | `0x01` |
| `5` | `1` | Algorithm ID | `0x01` (`AES256_GCM`), `0x02` (`XCHACHA20_POLY1305`) |
| `6` | `8` | Key Epoch | Big-endian 64-bit monotonic epoch |
| `14` | `N` | AEAD Ciphertext | Nonce/IV + ciphertext + authentication tag |

### Associated Data (AAD) Binding

Before encryption and decryption, the library builds a length-prefixed AAD buffer:

```text
len("EDST_AAD_V1") || "EDST_AAD_V1" ||
len(storeName)     || storeName     ||
header[0..13]                       ||
len(userAad)       || userAad
```

This prevents:
1. **Cross-store ciphertext swapping** (moving `cache.edst` over `auth.edst`).
2. **Algorithm downgrade / header tampering** (changing version, algorithm byte, or epoch fails AEAD tag verification).
3. **Truncation attacks** (0-byte existing files fail closed with `StoreTamperedOrCorruptedException`).
4. **Cross-tenant/user replay** when `associatedDataProvider` binds `userId` or `tenantId`.

---

## 3. OEM Keystore Failure & Biometric Auth Classification

`AndroidKeyStoreAead` distinguishes transient authentication locks from permanent corruption:

- `UserNotAuthenticatedException` → throws `UserAuthenticationRequiredException`. **Never** triggers corruption recovery or data wiping.
- `android.security.keystore.KeyPermanentlyInvalidatedException` → throws `KeyPermanentlyInvalidatedException`.
- `AEADBadTagException` → throws `StoreTamperedOrCorruptedException`.
- `KeyStoreException` / `UnrecoverableKeyException` / `ProviderException` → throws `KeystoreUnavailableException`.

Recovery behavior is strictly governed by `KeystoreRecoveryPolicy`:
- `STRICT` (default): Fails closed.
- `CLEAR_AND_REGENERATE`: Atomically deletes corrupted key files + `.edst`, regenerates keys, resets to `defaultValue`, and calls `onRecovery`.
- `EXPLICIT_SOFTWARE_FALLBACK`: Opt-in resilience for broken OEM Keystores. Derives a software KEK via HKDF-SHA256 over an installation-unique 256-bit CSPRNG secret in `noBackupFilesDir`, emits `SecurityEvent.SoftwareFallbackActivated`, and reports `SecurityLevel.SOFTWARE_FALLBACK` in `diagnostics()`.

---

## 4. Key Rotation & Memory Hygiene

- **Automatic Rotation:** Triggered by key age (`maxKeyAge`) or write count (`maxWritesBeforeRotation`) stored in AEAD-authenticated metadata (`<storeName>.meta`) to prevent timestamp/counter rollback.
- **Atomic Re-encryption:** `rotateKeys()` increments the key epoch and forces DataStore to atomically write and `fsync` a fresh encrypted envelope under the new primary key while pruning keys beyond `maxRetainedKeys`.
- **Secure Wipe (`clearAndReset`):** Overwrites persisted state with `defaultValue` under a new key epoch and destroys all historical keys so prior ciphertext snapshots become undecryptable.
- **Transient Buffer Wiping:** Serialized plaintext JSON `ByteArray` buffers are zeroed via `ByteArray.wipe()` in `finally` blocks immediately after encryption/decryption.
