# MaigSecurityCrypto

A modern, security-first **Kotlin Multiplatform (Android, JVM, iOS)** replacement for Android's deprecated `androidx.security:security-crypto` (`EncryptedSharedPreferences` and `EncryptedFile`), built on **Jetpack DataStore (Okio)**, **Google Tink**, **AndroidKeyStore / StrongBox**, and **iOS Keychain**.

- **Minimum Android SDK:** API 23 (Android 6.0+) — StrongBox hardware support on API 28+
- **Kotlin Package / Android Namespace:** `io.github.maigsecuritycrypto`
- **Targets:** `android`, `jvm`, `iosArm64`, `iosSimulatorArm64`
- **License:** Apache 2.0

---

## Table of Contents

- [Why MaigSecurityCrypto?](#why-maigsecuritycrypto)
- [Installation (Direct from GitHub)](#installation-direct-from-github)
  - [Option A: JitPack (Android & JVM)](#option-a-jitpack-android--jvm)
  - [Option B: Version Catalog (`libs.versions.toml`)](#option-b-version-catalog-libsversionstoml)
  - [Option C: GitHub Packages (Full KMP including iOS)](#option-c-github-packages-full-kmp-including-ios)
- [Tutorials & Usage](#tutorials--usage)
  - [1. Replacing `EncryptedSharedPreferences` (`MaigEncryptedPreferences`)](#1-replacing-encryptedsharedpreferences-maigencryptedpreferences)
  - [2. Using `MaigEncryptedPreferences` in Jetpack Compose](#2-using-maigencryptedpreferences-in-jetpack-compose)
  - [3. Typed `@Serializable` Object Store (`MaigEncryptedDataStore<T>`)](#3-typed-serializable-object-store-maigencrypteddatastoret)
  - [4. Migrating from Legacy `SharedPreferences` / `EncryptedSharedPreferences`](#4-migrating-from-legacy-sharedpreferences--encryptedsharedpreferences)
  - [5. Choosing a `MaigKeystoreRecoveryPolicy` (OEM Resilience)](#5-choosing-a-maigkeystorerecoverypolicy-oem-resilience)
  - [6. Key Rotation, Auditing Diagnostics & Secure Logout (`clearAndReset`)](#6-key-rotation-auditing-diagnostics--secure-logout-clearandreset)
  - [7. Biometric & Device Credential Binding (`MaigUserAuthConfig`)](#7-biometric--device-credential-binding-maiguserauthconfig)
  - [8. Kotlin Multiplatform Setup (Android, iOS & JVM)](#8-kotlin-multiplatform-setup-android-ios--jvm)
- [Upgrading from `0.2.x` (`EncryptedDataStore` -> `MaigSecurityCrypto`)](#upgrading-from-02x-encrypteddatastore---maigsecuritycrypto)
- [Publishing a Release from GitHub](#publishing-a-release-from-github)
- [FAQ & Best Practices](#faq--best-practices)
- [Sample App & Running Tests](#sample-app--running-tests)

---

## Why MaigSecurityCrypto?

- **Drop-in replacement for `EncryptedSharedPreferences`:** Reactive, type-safe `MaigEncryptedPreferences` supporting `String`, `Int`, `Long`, `Float`, `Double`, `Boolean`, `Set<String>`, `ByteArray`, and `@Serializable` objects.
- **Envelope Encryption (KEK + DEK):**
  - **Android:** 256-bit AES-GCM master key in `AndroidKeyStore` (StrongBox on API 28+ with automatic fallback to TEE) wrapping a Google Tink DEK keyset (`AES256_GCM` or `XCHACHA20_POLY1305`).
  - **iOS:** 256-bit CSPRNG DEKs (`SecRandomCopyBytes`) stored in the iOS Keychain (`*ThisDeviceOnly`) with `AES256_CTR_HMAC_SHA256` Encrypt-then-MAC via Apple `CommonCrypto` (`cryptography-provider-apple`).
  - **JVM:** Google Tink keyset wrapped with PBKDF2-HMAC-SHA256 (`310,000` iterations) when a passphrase provider is configured, or an isolated local AES-256-GCM KEK.
- **Authenticated Binary Envelope (`EDST` v1):** Binds the 14-byte header (magic, format version, cipher algorithm, key epoch), domain tag, `storeName`, and optional caller AAD (e.g., `userId`/`tenantId`) into the AEAD Associated Data to block file-swapping, truncation, and algorithm downgrade attacks.
- **Zero Cloud Backup Leaks by Default:** Stores encrypted files, keysets, and metadata in `noBackupFilesDir` (`0700`/`0600` permissions) on Android, and sets `NSURLIsExcludedFromBackupKey = true` on iOS.
- **Key Rotation & Secure Wipe:** Supports manual (`rotateKeys()`) and automatic (`MaigKeyRotationPolicy.Automatic` by age or write count) key rotation, plus `clearAndReset()` which destroys historical keys.
- **R8 / ProGuard Ready:** Consumer keep rules (`consumer-rules.pro`) are automatically bundled in the AAR.

---

## Installation (Direct from GitHub)

Consumers can add **MaigSecurityCrypto** via Gradle without cloning this repository locally.

### Option A: JitPack (Android & JVM)

1. Add the JitPack repository to your root `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

2. Add the dependency to your module's `build.gradle.kts`:

**Android app/library (`app/build.gradle.kts`):**
```kotlin
dependencies {
    implementation("com.github.Maignardi:MaigSecurityCrypto:0.3.1")
}
```

> **Note for Kotlin Multiplatform (`ios` + `android` + `jvm`):** JitPack builds on Linux and publishes Android and JVM artifacts only. If your KMP `commonMain` targets iOS as well, use **GitHub Packages** (Option C below) or depend on `com.github.Maignardi:MaigSecurityCrypto:0.3.1` inside `androidMain` / `jvmMain` when using JitPack.

### Option B: Version Catalog (`libs.versions.toml`)

```toml
[versions]
maigSecurityCrypto = "0.3.1"

[libraries]
maig-security-crypto = { module = "com.github.Maignardi:MaigSecurityCrypto", version.ref = "maigSecurityCrypto" }
```

```kotlin
dependencies {
    implementation(libs.maig.security.crypto)
}
```

### Option C: GitHub Packages (Full KMP including iOS)

Tagging `v*` triggers [`.github/workflows/publish.yml`](.github/workflows/publish.yml) to publish Android, JVM, and iOS artifacts to GitHub Packages:

```kotlin
repositories {
    google()
    mavenCentral()
    maven {
        url = uri("https://maven.pkg.github.com/Maignardi/MaigSecurityCrypto")
        credentials {
            username = providers.gradleProperty("gpr.user").orNull ?: System.getenv("GITHUB_ACTOR")
            password = providers.gradleProperty("gpr.key").orNull ?: System.getenv("GITHUB_TOKEN")
        }
    }
}

dependencies {
    implementation("io.github.maignardi:MaigSecurityCrypto:0.3.1")
}
```

---

## Tutorials & Usage

### 1. Replacing `EncryptedSharedPreferences` (`MaigEncryptedPreferences`)

Create **one singleton instance per `storeName`** (e.g., via Hilt, Koin, or an `Application`-scoped property), following Jetpack DataStore's single-instance rule:

```kotlin
import io.github.maigsecuritycrypto.*
import kotlin.time.Duration.Companion.days

val authPrefs: MaigEncryptedPreferences = MaigSecurityCrypto.createPreferences(
    context = MaigStorageContext(applicationContext),
    config = MaigSecurityConfig(
        storeName = "auth_prefs",
        algorithm = MaigCipherAlgorithm.AES256_GCM, // or MaigCipherAlgorithm.XCHACHA20_POLY1305
        keyRotationPolicy = MaigKeyRotationPolicy.Automatic(
            maxKeyAge = 90.days,
            maxWritesBeforeRotation = 100_000L,
            maxRetainedKeys = 2,
        ),
        recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
    ),
)
```

Define type-safe keys and read/write atomically:

```kotlin
@Serializable
data class UserProfile(val id: Long, val email: String)

object AuthKeys {
    val accessToken = MaigPreferenceKeys.string("access_token")
    val expiresAt = MaigPreferenceKeys.long("expires_at")
    val loginCount = MaigPreferenceKeys.int("login_count")
    val biometricEnabled = MaigPreferenceKeys.boolean("biometric_enabled")
    val scopes = MaigPreferenceKeys.stringSet("scopes")
    val deviceSeed = MaigPreferenceKeys.byteArray("device_seed")
    val profile = MaigPreferenceKeys.serializable("profile", UserProfile.serializer())
}

// Atomic transactional write
authPrefs.edit { prefs ->
    prefs[AuthKeys.accessToken] = "eyJhbGciOi..."
    prefs[AuthKeys.expiresAt] = 1_800_000_000L
    prefs[AuthKeys.biometricEnabled] = true
    prefs[AuthKeys.scopes] = setOf("read", "write")
    prefs[AuthKeys.profile] = UserProfile(id = 42L, email = "ada@example.com")
}

// One-shot read
val token: String? = authPrefs.get(AuthKeys.accessToken)

// Remove a single key
authPrefs.edit { prefs ->
    prefs.remove(AuthKeys.accessToken)
    // or: prefs[AuthKeys.accessToken] = null
}

// Reactive observation (only emits when accessToken actually changes)
authPrefs.observe(AuthKeys.accessToken).collect { currentToken ->
    // Update auth state or HTTP client
}
```

#### All Supported `MaigPreferenceKeys` Builders

| Builder | Kotlin Type |
| --- | --- |
| `MaigPreferenceKeys.string(name)` | `String` |
| `MaigPreferenceKeys.int(name)` | `Int` |
| `MaigPreferenceKeys.long(name)` | `Long` |
| `MaigPreferenceKeys.float(name)` | `Float` |
| `MaigPreferenceKeys.double(name)` | `Double` |
| `MaigPreferenceKeys.boolean(name)` | `Boolean` |
| `MaigPreferenceKeys.stringSet(name)` | `Set<String>` |
| `MaigPreferenceKeys.byteArray(name)` | `ByteArray` |
| `MaigPreferenceKeys.serializable(name, serializer)` | Any `@Serializable` type `T` |

---

### 2. Using `MaigEncryptedPreferences` in Jetpack Compose

```kotlin
@Composable
fun TokenStatusBanner(prefs: MaigEncryptedPreferences) {
    val scope = rememberCoroutineScope()
    val token by prefs.observe(AuthKeys.accessToken).collectAsState(initial = null)

    Column {
        Text(text = if (token != null) "Session Active" else "Signed Out")
        Button(onClick = {
            scope.launch { prefs.clearAndReset() }
        }) {
            Text("Log Out Securely")
        }
    }
}
```

See [`EncryptedVaultScreen.kt`](sample-android/src/main/kotlin/io/github/maigsecuritycrypto/sample/EncryptedVaultScreen.kt) for a full working Compose example.

---

### 3. Typed `@Serializable` Object Store (`MaigEncryptedDataStore<T>`)

For structured domain models, use `MaigSecurityCrypto.create(...)`. You can also pass `associatedDataProvider` to cryptographically bind ciphertext to a user or tenant ID (preventing cross-account file replay):

```kotlin
@Serializable
data class SessionState(
    val accessToken: String = "",
    val refreshToken: String = "",
    val userId: String = "",
)

val sessionStore: MaigEncryptedDataStore<SessionState> = MaigSecurityCrypto.create(
    context = MaigStorageContext(applicationContext),
    config = MaigSecurityConfig(
        storeName = "session_state",
        associatedDataProvider = { currentTenantId.encodeToByteArray() },
    ),
    serializer = SessionState.serializer(),
    defaultValue = { SessionState() },
)

// Update atomically
sessionStore.updateData { current ->
    current.copy(accessToken = "new_access_token")
}

// Read once or collect Flow<SessionState>
val currentSession: SessionState = sessionStore.get()
```

> **Warning on `associatedDataProvider`:** `associatedDataProvider` is evaluated on **every** read and write. Ensure the value it returns is deterministic across app restarts (for example, an already-resolved `userId` or `tenantId`). If the returned bytes differ on a later read, decryption fails with `MaigStoreTamperedOrCorruptedException` — and under `CLEAR_AND_REGENERATE`, that mismatch wipes and resets the store. For per-user isolation across logins, prefer a scoped `storeName` such as `"session_$userId"`.

---

### 4. Migrating from Legacy `SharedPreferences` / `EncryptedSharedPreferences`

Upgrade existing users smoothly without losing saved tokens or settings. The source `SharedPreferences` is cleared **only after** the encrypted DataStore transaction commits:

```kotlin
// Option A: DataStore-integrated migration (runs atomically before first read)
val authPrefs = MaigSecurityCrypto.createPreferences(
    context = MaigStorageContext(applicationContext),
    config = MaigSecurityConfig(storeName = "auth_prefs"),
    migrations = listOf(
        MaigSharedPreferencesDataMigration(
            source = legacyEncryptedPrefs,
            migrationId = "legacy_auth_prefs",
            clearSourceOnSuccess = true,
        )
    ),
)

// Option B: Imperative migration (wipes legacy file only after encrypted write commits)
val report: MaigSharedPreferencesMigrationReport = authPrefs.migrateFromSharedPreferences(
    source = legacyEncryptedPrefs,
    clearSourceOnSuccess = true,
    overwriteExisting = false,
)

// Optional: migrate only specific keys
val partialReport = authPrefs.migrateFromSharedPreferences(
    source = legacyPrefs,
    keysToMigrate = setOf("access_token", "refresh_token"),
    clearSourceOnSuccess = true,
)
```

---

### 5. Choosing a `MaigKeystoreRecoveryPolicy` (OEM Resilience)

Some Android OEMs suffer from `AndroidKeyStore` bugs (keys invalidated after OS updates or unavailable Keystore services). `MaigSecurityCrypto` never weakens security or wipes data silently — choose the policy that matches your threat model:

| Policy | Behavior on Keystore / File Corruption | Recommended For |
| --- | --- | --- |
| `MaigKeystoreRecoveryPolicy.STRICT` *(Default)* | Fails closed by throwing `MaigSecurityStorageException` (`MaigKeystoreUnavailableException` / `MaigStoreTamperedOrCorruptedException`). | High-security secrets, banking/payment tokens where silent resets are unacceptable. |
| `MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE` | Atomically wipes the corrupted keyset and store file, generates fresh keys, resets to default value, and calls `onRecovery`. | Session caches or tokens where the user can cleanly re-authenticate after OS Keystore corruption. |
| `MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK` | Explicit opt-in for broken OEM Keystores (cannot be combined with `MaigUserAuthConfig`): derives an app-scoped software KEK via HKDF-SHA256 over an installation-unique CSPRNG secret in `noBackupFilesDir`, and reports `MaigSecurityLevel.SOFTWARE_FALLBACK` in `diagnostics()`. | Non-critical preferences or apps targeting devices with known broken hardware Keystores. |

```kotlin
val config = MaigSecurityConfig(
    storeName = "resilient_session",
    recoveryPolicy = MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
    onRecovery = { event ->
        // Log redacted reason and prompt user to sign in again
        analytics.log("store_reset", mapOf("store" to event.storeName))
    },
    eventListener = { event ->
        // Redacted audit events (never contain keys or plaintext)
        when (event) {
            is MaigSecurityEvent.StrongBoxFallbackToTee -> { /* StrongBox unavailable, TEE used */ }
            is MaigSecurityEvent.KeyRotated -> { /* Key rotated from oldEpoch to newEpoch */ }
            is MaigSecurityEvent.SoftwareFallbackActivated -> { /* Software fallback active */ }
            else -> Unit
        }
    },
)
```

---

### 6. Key Rotation, Auditing Diagnostics & Secure Logout (`clearAndReset`)

```kotlin
// 1. Force immediate key rotation & atomic file re-encryption under a new epoch
val newEpoch: Long = authPrefs.rotateKeys()

// 2. Inspect active security posture (safe for debug panels/telemetry; zero secrets exposed)
val diag: MaigSecurityDiagnostics = authPrefs.diagnostics()
// diag.securityLevel -> STRONGBOX / HARDWARE_TEE / KEYCHAIN / PASSPHRASE_PBKDF2 / LOCAL_FILE_KEK / SOFTWARE_FALLBACK / UNKNOWN
// diag.hardwareBacked -> true on Android StrongBox/TEE; false on software fallback, JVM, or iOS Keychain (DEK used in app memory)
// diag.currentKeyEpoch -> 2
// diag.writesSinceRotation -> 0

// 3. Secure logout: overwrites store with default state AND destroys all prior DEKs
// Even an attacker holding an older disk snapshot cannot decrypt it afterward.
authPrefs.clearAndReset()

// 4. Escape hatch for permanently invalidated/corrupted STRICT stores:
// Wipes disk files and keys without attempting to decrypt, then closes this instance.
brokenStore.forceResetAndClose()
```

---

### 7. Biometric & Device Credential Binding (`MaigUserAuthConfig`)

Bind the AndroidKeyStore master key to recent biometric or lockscreen authentication:

```kotlin
val biometricVault = MaigSecurityCrypto.createPreferences(
    context = MaigStorageContext(applicationContext),
    config = MaigSecurityConfig(
        storeName = "biometric_vault",
        userAuthConfig = MaigUserAuthConfig(
            authValidityDurationSeconds = 30,
            allowDeviceCredential = true,
            invalidateOnBiometricEnrollment = true,
        ),
    ),
)
```

> **Important:**
> - `authValidityDurationSeconds` must be `> 0` (per-operation `0`-second keys require `BiometricPrompt.CryptoObject`, which DataStore streams do not expose).
> - Because `DataStore` caches decrypted values in RAM once loaded in the active process, `authValidityDurationSeconds` enforces biometric/credential re-authentication on **initial store unlock** and on **subsequent writes or key rotations** after the window expires (and when a fresh store instance is opened), while active `data` / `get()` readers continue receiving the in-memory cached state until the process restarts.
> - On Android, when `userAuthConfig` is enabled, the DEK keyset is **not** cached in RAM across operations. On iOS, Keychain items use `SecAccessControl` paired with a shared `LAContext` configured with `touchIDAuthenticationAllowableReuseDuration = authValidityDurationSeconds`.
> - When the device is locked, authentication expired, or the user cancels the biometric prompt (`errSecUserCanceled` on iOS), operations throw `MaigUserAuthenticationRequiredException`. This transient state **never** triggers corruption recovery or store wiping — prompt authentication and retry.

---

### 8. Kotlin Multiplatform Setup (Android, iOS & JVM)

Instantiate `MaigStorageContext` per platform and share your store factory in `commonMain`:

```kotlin
// commonMain (uses AES256_GCM on Android/JVM and AES256_CTR_HMAC_SHA256 on iOS by default;
// pass MaigCipherAlgorithm.AES256_CTR_HMAC_SHA256 explicitly if you need the same algorithm across all platforms)
class VaultRepository(context: MaigStorageContext) {
    val prefs = MaigSecurityCrypto.createPreferences(
        context = context,
        config = MaigSecurityConfig(
            storeName = "shared_vault",
            iosAccessibility = MaigIosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
        ),
    )
}

// androidMain
VaultRepository(MaigStorageContext(applicationContext))

// iosMain
VaultRepository(MaigStorageContext())

// jvmMain (optionally protect the Tink keyset with a PBKDF2 passphrase)
VaultRepository(
    MaigStorageContext(
        storageDirectory = File(System.getProperty("user.home"), ".myapp"),
        masterPassphraseProvider = { promptPassphrase() },
    )
)
```

---

## Upgrading from `0.2.x` (`EncryptedDataStore` -> `MaigSecurityCrypto`)

In `0.3.x`, the library was renamed to **MaigSecurityCrypto**:
- Starting in `0.3.1`, update the repository/Gradle coordinates to `com.github.Maignardi:MaigSecurityCrypto:0.3.1` (JitPack) or `io.github.maignardi:MaigSecurityCrypto:0.3.1` (GitHub Packages).
- Existing `.edst` encrypted files, `AndroidKeyStore` aliases, and iOS Keychain items stay **100% compatible** — users upgrading in-place keep all stored data.
- Update imports from `io.github.encrypteddatastore.*` to `io.github.maigsecuritycrypto.*` and rename public symbols (`EncryptedDataStoreFactory` -> `MaigSecurityCrypto`, `EncryptedPreferences` -> `MaigEncryptedPreferences`, `EncryptedDataStore` -> `MaigEncryptedDataStore`, `SecurityConfig` -> `MaigSecurityConfig`, `PlatformStorageContext` -> `MaigStorageContext`, etc.).

---

## Publishing a Release from GitHub

1. Push changes to `Maignardi/MaigSecurityCrypto`.
2. Create and push a version tag:
   ```bash
   git tag 0.3.1
   git push origin 0.3.1
   ```
3. **JitPack:** Anyone can immediately add `implementation("com.github.Maignardi:MaigSecurityCrypto:0.3.1")` — JitPack reads [`jitpack.yml`](jitpack.yml), builds with JDK 21 + Android SDK 35, and publishes the Android, JVM, and KMP artifacts automatically.
4. **GitHub Packages:** Push a `v*` tag (e.g. `v0.3.1`) to trigger [`.github/workflows/publish.yml`](.github/workflows/publish.yml), publishing all targets including iOS.

---

## FAQ & Best Practices

- **Why do I get `IllegalStateException: There are multiple DataStores active for the same file`?**
  Jetpack DataStore requires a single active instance per file path per process. Create each `MaigEncryptedDataStore` / `MaigEncryptedPreferences` once as a singleton (Hilt `@Singleton`, Koin `single`, or `object` / `Application` property). In unit tests that reopen the same store path, call `suspend fun close()` before creating a new instance.
- **Do I need extra ProGuard / R8 rules?**
  No. [`consumer-rules.pro`](MaigSecurityCrypto/consumer-rules.pro) is embedded inside the published AAR (`proguard.txt`) and applied automatically in release builds.
- **Are files excluded from Android Auto Backup?**
  Yes. By default, encrypted `.edst` payloads, `.keyset` files, and `.meta` files are stored in `context.noBackupFilesDir` with `0700`/`0600` POSIX permissions.

---

## Sample App & Running Tests

- [`sample-android`](sample-android) provides a Jetpack Compose Material 3 app (`EncryptedVaultScreen`) and Compose UI tests (`EncryptedVaultScreenTest`).
- Run the full verification suite:

```bash
./gradlew :MaigSecurityCrypto:jvmTest :MaigSecurityCrypto:testAndroidHostTest :MaigSecurityCrypto:verifyAndroidMinSdk23Compatibility :sample-android:testDebugUnitTest
```

See [`SECURITY.md`](SECURITY.md) for the cryptographic specification, envelope layout, and threat model.
