# Changelog

All notable changes to this project will be documented in this file.

## [0.3.1] - 2026-11-18

### Breaking Changes
- **Repository, Gradle module & Maven coordinates renamed to `MaigSecurityCrypto`:**
  - GitHub repository moved to `https://github.com/Maignardi/MaigSecurityCrypto`
  - Gradle module renamed from `:encrypted-datastore` to `:MaigSecurityCrypto` (`rootProject.name = "MaigSecurityCrypto-root"`)
  - **JitPack:** `com.github.Maignardi:MaigSecurityCrypto:0.3.1`
  - **GitHub Packages:** `io.github.maignardi:MaigSecurityCrypto:0.3.1`

## [0.3.0] - 2026-11-18

### Breaking Changes (Rebrand to MaigSecurityCrypto)
- **Library renamed to `MaigSecurityCrypto`:**
  - Kotlin package & Android `namespace` changed from `io.github.encrypteddatastore` to `io.github.maigsecuritycrypto`.
  - Public API classes renamed/prefixed for clarity:
    - `EncryptedDataStoreFactory` -> `MaigSecurityCrypto`
    - `EncryptedDataStore<T>` -> `MaigEncryptedDataStore<T>`
    - `EncryptedPreferences` / `EncryptedPreferencesSnapshot` / `MutableEncryptedPreferences` / `EncryptedPreferencesMigration` -> `MaigEncryptedPreferences` / `MaigEncryptedPreferencesSnapshot` / `MaigMutableEncryptedPreferences` / `MaigEncryptedPreferencesMigration`
    - `PreferenceKey` / `PreferenceKeys` -> `MaigPreferenceKey` / `MaigPreferenceKeys`
    - `PlatformStorageContext` -> `MaigStorageContext`
    - `SharedPreferencesDataMigration` / `SharedPreferencesMigrationReport` -> `MaigSharedPreferencesDataMigration` / `MaigSharedPreferencesMigrationReport`
    - `SecurityConfig`, `CipherAlgorithm`, `KeystoreRecoveryPolicy`, `KeyRotationPolicy`, `SecurityLevel`, `UserAuthConfig`, `IosKeychainAccessibility`, `RecoveryEvent`, `SecurityEvent`, `SecurityEventListener`, `SecurityDiagnostics` -> `Maig*` prefixed equivalents
    - `SecurityStorageException` and subclasses -> `Maig*` prefixed equivalents
  - Gradle/Maven coordinates (`com.github.Maignardi:encrypted-datastore` on JitPack, `io.github.maignardi:encrypted-datastore` on GitHub Packages) remain unchanged.
  - On-disk `.edst` envelope format, `AndroidKeyStore` aliases, and iOS Keychain service identifiers are preserved for seamless upgrades from `0.2.x`.

### Fixed
- **Documentation:** Clarified in `README.md` that iOS uses `AES256_CTR_HMAC_SHA256` Encrypt-then-MAC via Apple `CommonCrypto` (`cryptography-provider-apple`).

## [0.2.2] - 2026-11-18

### Fixed
- **CI `Publish to GitHub Packages` workflow:** Replaced Bash 4 `${OWNER,,}` with POSIX-compatible `tr` so `publish.yml` succeeds on `macos-15` Bash 3.2.
- **Android instrumented tests (`AndroidKeyStoreInstrumentedTest`):** Added `@Before` test cleanup and emulator detection so software-emulated `KeyInfo` on Android Emulator AVDs is handled accurately while physical devices still assert hardware-backed TEE/StrongBox.
- **Full API 23 bytecode verification:** Replaced the custom two-package token scan with **Animal Sniffer** (`org.codehaus.mojo:animal-sniffer` + `com.toasttab.android:gummy-bears-api-23`), isolating `Build.VERSION.SDK_INT`-gated Android KeyStore API 24/28/30/31 calls into `AndroidKeyStoreApiCompat.kt` and removing the no-op `lint` block from the KMP library build script.

## [0.2.1] - 2026-11-18

### Breaking Changes
- `SharedPreferencesDataMigration` now requires an explicit `migrationId: String` parameter (removed the default `"shared_prefs_default"` value) so multiple `SharedPreferences` sources cannot silently collide on migration completion tracking.

### Added
- `verifyAndroidMinSdk23Compatibility` Gradle verification task (wired to `check` and CI) scanning `androidMain` compiled classes for API 26+ `java.nio.file` / `java.time` references, since `com.android.kotlin.multiplatform.library` does not run standalone lint reports on `androidMain`.
- Independent Known-Answer Test (KAT) vector for `IosAesCtrHmacCipher` generated externally with Python `hmac`/`hashlib` and `openssl enc -aes-256-ctr`.
- Real `AndroidKeyStore` instrumented test suite in `androidDeviceTest` (`AndroidKeyStoreInstrumentedTest`) and an `android-emulator` job in GitHub Actions CI.

### Fixed
- `EncryptedPreferences.clearAndReset()` now preserves `completedMigrations` so legacy `SharedPreferences` (when `clearSourceOnSuccess = false`) do not re-import old data on the next app launch after logout.

## [0.2.0] - 2026-11-18

### Breaking Changes (Cumulative vs 0.1.0)
- **iOS default cipher algorithm changed to `CipherAlgorithm.AES256_CTR_HMAC_SHA256`:** `cryptography-provider-apple` wraps Apple `CommonCrypto`, which does not provide `AES-GCM`. `IosKeychainKeyManager` uses `AES-256-CTR + HMAC-SHA256` Encrypt-then-MAC (`IosAesCtrHmacCipher`) and explicitly rejects `AES256_GCM` and `XCHACHA20_POLY1305` on iOS. `SecurityConfig.algorithm` defaults per platform (`AES256_GCM` on Android/JVM, `AES256_CTR_HMAC_SHA256` on iOS).
- **`SecurityConfig` is no longer a `data class`:** Converted to a regular class with explicit `equals`/`hashCode`/`toString` excluding lambda callbacks (`copy()` was removed).
- **`PlatformStorageContext` (`androidMain`):** Removed `useNoBackupDir` constructor parameter; Android stores always use `noBackupFilesDir`.
- **`SecurityLevel` enum:** Removed unused `SECURE_ENCLAVE` and misleading `JVM_KEYSTORE`; added `PASSPHRASE_PBKDF2`, `LOCAL_FILE_KEK`, and `UNKNOWN`.
- **`SharedPreferencesMigrationReport`:** Added `skippedExistingKeys: Set<String>` property.
- **Tightened configuration validation:** `KeyRotationPolicy.Automatic` requires `maxRetainedKeys >= 2`; `UserAuthConfig` requires `authValidityDurationSeconds > 0`; `EXPLICIT_SOFTWARE_FALLBACK` cannot be combined with `UserAuthConfig`.

### Added
- `forceResetAndClose()` on `EncryptedDataStore` and `EncryptedPreferences` to wipe corrupted/invalidated `STRICT` stores without decrypting or eagerly recreating auth-bound keys.
- `EncryptedPreferencesMigration` interface and `SharedPreferencesDataMigration` integrated with Jetpack `DataStore`'s `DataMigration` pipeline.
- Expiring `LAContext` management (`invalidate()` after `authValidityDurationSeconds`) on iOS Keychain authentication.

### Fixed
- **Android API 23–25 compatibility:** Replaced `java.nio.file.*` (`API 26+`) in `AndroidTinkKeyManager.atomicWriteFile` with `android.system.Os` (`open`/`chmod`/`rename`/`fsync`) plus safe rename fallback for Robolectric.
- **JVM backward compatibility:** Reverted JVM keyset/metadata AAD to `storeName` (matching `0.1.0`/`0.1.1`), with automatic migration for any `0.1.2` keyset.
- **JVM passphrase handling:** Unvalidated KEKs are no longer cached on `parseEncryptedKeyset` failure, wrong passphrases never trigger `CLEAR_AND_REGENERATE` wipes, and caller `CharArray` buffers are copied before wiping.
- **Recovery safety:** Transient `KeystoreUnavailableException`, `KeyManagementException`, and `UserAuthenticationRequiredException` (including iOS `errSecUserCanceled`) never trigger `CLEAR_AND_REGENERATE` data wipes.
- **Sample app:** Moved `EncryptedPreferences` singleton into `SampleApplication` to prevent `DataStore` multi-instance crashes on rotation.

## [0.1.2] - 2026-11-18
- Attempted `android.system.Os` atomic writes, `forceResetAndClose()`, `LAContext` reuse on iOS, and `SharedPreferencesDataMigration` (superseded by `0.2.0` due to breaking iOS cipher change and JVM AAD regression).

## [0.1.1] - 2026-11-18
- Hardened `EXPLICIT_SOFTWARE_FALLBACK` against `UserAuthConfig`, added `CharArray` copy in JVM PBKDF2, moved `SampleApplication` singleton setup, and added `iosSimulatorArm64Test`.

## [0.1.0] - 2026-11-18
- Initial release with `EncryptedDataStore`, `EncryptedPreferences`, authenticated `EDST` binary envelope, Google Tink, `AndroidKeyStore`/StrongBox, iOS Keychain, and JVM PBKDF2 support.
