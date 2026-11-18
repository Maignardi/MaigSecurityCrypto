# Security Architecture & Threat Model

## 1. Key Hierarchy (Envelope Encryption)

`EncryptedDataStore` separates the **Key Encryption Key (KEK)** from the **Data Encryption Key (DEK)**:

- **Android (`androidMain`)**:
  - **KEK:** 256-bit AES-GCM key generated inside `AndroidKeyStore` (`setRandomizedEncryptionRequired(true)`).
    - Requests StrongBox (`SECURITY_LEVEL_STRONGBOX`) on API 28+ when `preferStrongBox = true` and `PackageManager.FEATURE_STRONGBOX_KEYSTORE` is present.
    - Gracefully falls back to TEE hardware Keystore (`SECURITY_LEVEL_TRUSTED_ENVIRONMENT`) if StrongBox generation fails (`StrongBoxUnavailableException`, `ProviderException`, or `KeyStoreException`), emitting `SecurityEvent.StrongBoxFallbackToTee`.
    - All `AndroidKeyStore` calls are serialized via an internal synchronization lock to prevent OEM concurrency crashes.
    - When `UserAuthConfig` is enabled, the DEK keyset is unwrapped on each access rather than cached in RAM so AndroidKeyStore's `authValidityDurationSeconds` timeout is enforced on initial unlock and subsequent writes/rotations (note: DataStore caches the decrypted value in RAM once loaded for active process readers).
  - **DEK:** Google Tink `KeysetHandle` (`AES256_GCM` or `XCHACHA20_POLY1305`) wrapped by the KEK using `TinkProtoKeysetFormat.serializeEncryptedKeyset` with domain-separated AAD (`packageName:storeName`), persisted atomically (`O_CREAT|O_WRONLY|O_TRUNC` with mode `0600` via `android.system.Os` -> `write -> flush -> fsync -> Os.rename -> directory fsync`) inside `noBackupFilesDir/encrypted_datastore/<storeName>.keyset` (compatible with API 23+).
- **iOS (`iosMain`)**:
  - **Algorithm:** `CipherAlgorithm.AES256_CTR_HMAC_SHA256` (Apple `CommonCrypto` via `cryptography-provider-apple`: AES-256-CTR + HMAC-SHA256 Encrypt-then-MAC with domain-separated subkeys, 16-byte CSPRNG IV, and constant-time tag verification before decryption). Passing `AES256_GCM` or `XCHACHA20_POLY1305` on iOS fails fast on initialization.
  - **DEK Keyset:** 256-bit CSPRNG (`SecRandomCopyBytes`) keys stored in the iOS Keychain (`kSecClassGenericPassword`) with `ThisDeviceOnly` accessibility (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` by default, or `SecAccessControl` paired with a shared `LAContext` using `touchIDAuthenticationAllowableReuseDuration` when `UserAuthConfig` is provided). Because the DEK is loaded into app memory for Apple `CommonCrypto` (`cryptography-provider-apple`), `diagnostics().hardwareBacked` honestly reports `false` (`SecurityLevel.KEYCHAIN`).
  - DataStore files are written inside `NSApplicationSupportDirectory/encrypted_datastore/` with `NSURLIsExcludedFromBackupKey = true` and `0700`/`0600` permissions.
- **JVM (`jvmMain`)**:
  - Uses Google Tink `KeysetHandle` wrapped with either a PBKDF2-HMAC-SHA256 key (`310,000` iterations, 32-byte CSPRNG salt, `SecurityLevel.PASSPHRASE_PBKDF2`) when `masterPassphraseProvider` is configured, or an isolated local AES-256-GCM KEK file (`0600`, `SecurityLevel.LOCAL_FILE_KEK`). Caller `CharArray` buffers returned by `masterPassphraseProvider` are copied before clearing so reusable caller arrays are never mutated, and derived KEKs are cached only after keyset decryption succeeds.

---

## 2. Authenticated Binary Envelope (`EDST` v1)

Every encrypted store payload uses a self-describing, authenticated binary framing:

| Offset | Length | Field | Notes |
| --- | --- | --- | --- |
| `0` | `4` | Magic | `"EDST"` (`0x45 0x44 0x53 0x54`) |
| `4` | `1` | Version | `0x01` |
| `5` | `1` | Algorithm ID | `0x01` (`AES256_GCM`), `0x02` (`XCHACHA20_POLY1305`), `0x03` (`AES256_CTR_HMAC_SHA256`) |
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
- `STRICT` (default): Fails closed. Use `forceResetAndClose()` for explicit user-confirmed wipe/reset.
- `CLEAR_AND_REGENERATE`: Triggers **only** on `StoreTamperedOrCorruptedException` or `KeyPermanentlyInvalidatedException` (never on `UserAuthenticationRequiredException`, `KeystoreUnavailableException`, or wrong-passphrase `KeyManagementException`). Atomically deletes corrupted key files + `.edst` via DataStore's `ReplaceFileCorruptionHandler`, regenerates keys, resets to `defaultValue`, and calls `onRecovery`.
- `EXPLICIT_SOFTWARE_FALLBACK`: Opt-in resilience for broken OEM Keystores (cannot be combined with `UserAuthConfig`). Derives a software KEK via HKDF-SHA256 over an installation-unique 256-bit CSPRNG secret in `noBackupFilesDir`, emits `SecurityEvent.SoftwareFallbackActivated`, and reports `SecurityLevel.SOFTWARE_FALLBACK` in `diagnostics()`.

---

## 4. Key Rotation & Memory Hygiene

- **Automatic Rotation:** Triggered by key age (`maxKeyAge`) or write count (`maxWritesBeforeRotation`) stored in AEAD-authenticated metadata (`<storeName>.meta`) to prevent timestamp/counter rollback.
- **Atomic Re-encryption:** `rotateKeys()` increments the key epoch and forces DataStore to atomically write and `fsync` a fresh encrypted envelope under the new primary key while pruning keys beyond `maxRetainedKeys`.
- **Secure Wipe (`clearAndReset`):** Overwrites persisted state with `defaultValue` under a new key epoch and destroys all historical keys so prior ciphertext snapshots become undecryptable.
- **Transient Buffer Wiping:** Serialized plaintext JSON `ByteArray` buffers (and temporary key/passphrase copies created by this library) are zeroed via `ByteArray.wipe()` in `finally` blocks immediately after encryption/decryption. Underlying cryptographic providers (Google Tink / JCA / Apple CryptoKit) and Swift/Kotlin immutable strings (`Base64` inside iOS Keychain JSON) manage their own memory lifecycles within JVM/Native runtime constraints.
