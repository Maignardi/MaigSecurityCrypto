# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-11-18

### Breaking Changes
- **iOS default cipher algorithm changed to `CipherAlgorithm.AES256_CTR_HMAC_SHA256`:** `cryptography-provider-apple` wraps Apple `CommonCrypto`, which does not provide `AES-GCM`. `IosKeychainKeyManager` now uses `AES-256-CTR + HMAC-SHA256` Encrypt-then-MAC (`IosAesCtrHmacCipher`) and rejects `AES256_GCM` / `XCHACHA20_POLY1305` explicitly on iOS. `SecurityConfig.algorithm` defaults per platform (`AES256_GCM` on Android/JVM, `AES256_CTR_HMAC_SHA256` on iOS).
- **Tightened configuration validation:** `KeyRotationPolicy.Automatic` requires `maxRetainedKeys >= 2`; `UserAuthConfig` requires `authValidityDurationSeconds > 0`; `EXPLICIT_SOFTWARE_FALLBACK` cannot be combined with `UserAuthConfig`.

### Added
- `forceResetAndClose()` on `EncryptedDataStore` and `EncryptedPreferences` to wipe corrupted/invalidated `STRICT` stores without decrypting or eagerly recreating auth-bound keys.
- `EncryptedPreferencesMigration` interface + `SharedPreferencesDataMigration` integrated with Jetpack `DataStore` `DataMigration` pipeline (including persistent `completedMigrations` tracking for `overwriteExisting = true` + `clearSourceOnSuccess = false`).
- Expiring `LAContext` management (`invalidate()` after `authValidityDurationSeconds`) on iOS Keychain authentication.
- Android Lint (`lintAndroidMain`) added to CI alongside JVM, Android host, Compose UI, and iOS simulator test suites.

### Fixed
- **Android API 23–25 compatibility:** Replaced `java.nio.file.*` (`API 26+`) in `AndroidTinkKeyManager.atomicWriteFile` with `android.system.Os` (`open`/`chmod`/`rename`/`fsync`) for full `minSdk = 23` compatibility.
- **JVM backward compatibility:** Reverted JVM keyset/metadata AAD to `storeName` (matching `0.1.0`/`0.1.1`), with automatic migration if an existing `0.1.2` keyset is encountered.
- **JVM passphrase handling:** Unvalidated KEKs are no longer cached on `parseEncryptedKeyset` failure, wrong passphrases never trigger `CLEAR_AND_REGENERATE` wipes, and caller `CharArray` buffers are copied before wiping.
- **Recovery safety:** Transient `KeystoreUnavailableException`, `KeyManagementException`, and `UserAuthenticationRequiredException` (including iOS `errSecUserCanceled`) never trigger `CLEAR_AND_REGENERATE` data wipes.
- **Sample app:** Moved `EncryptedPreferences` singleton into `SampleApplication` to prevent `DataStore` multi-instance crashes on configuration changes.

## [0.1.0] - 2026-11-18
- Initial release with `EncryptedDataStore`, `EncryptedPreferences`, authenticated `EDST` binary envelope, Google Tink, `AndroidKeyStore`/StrongBox, iOS Keychain, and JVM PBKDF2 support.
