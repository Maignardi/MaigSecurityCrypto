# EncryptedDataStore

A modern, security-first **Kotlin Multiplatform (Android, JVM, iOS)** replacement for Android's deprecated `androidx.security:security-crypto` (`EncryptedSharedPreferences` and `EncryptedFile`), built on **Jetpack DataStore (Okio)**, **Google Tink**, **AndroidKeyStore / StrongBox**, and **iOS Keychain**.

- **Minimum Android SDK:** API 23 (Android 6.0+) — StrongBox hardware support on API 28+
- **Targets:** `android`, `jvm`, `iosArm64`, `iosSimulatorArm64`, `iosX64`
- **License:** Apache 2.0

---

## Table of Contents

- [Why EncryptedDataStore?](#why-encrypteddatastore)
- [Installation (Direct from GitHub)](#installation-direct-from-github)
  - [Option A: JitPack (Android & JVM)](#option-a-jitpack-android--jvm)
  - [Option B: Version Catalog (`libs.versions.toml`)](#option-b-version-catalog-libsversionstoml)
  - [Option C: GitHub Packages (Full KMP including iOS)](#option-c-github-packages-full-kmp-including-ios)
- [Tutorials & Usage](#tutorials--usage)
  - [1. Replacing `EncryptedSharedPreferences` (`EncryptedPreferences`)](#1-replacing-encryptedsharedpreferences-encryptedpreferences)
  - [2. Using `EncryptedPreferences` in Jetpack Compose](#2-using-encryptedpreferences-in-jetpack-compose)
  - [3. Typed `@Serializable` Object Store (`EncryptedDataStore<T>`)](#3-typed-serializable-object-store-encrypteddatastoret)
  - [4. Migrating from Legacy `SharedPreferences` / `EncryptedSharedPreferences`](#4-migrating-from-legacy-sharedpreferences--encryptedsharedpreferences)
  - [5. Choosing a `KeystoreRecoveryPolicy` (OEM Resilience)](#5-choosing-a-keystorerecoverypolicy-oem-resilience)
  - [6. Key Rotation, Auditing Diagnostics & Secure Logout (`clearAndReset`)](#6-key-rotation-auditing-diagnostics--secure-logout-clearandreset)
  - [7. Biometric & Device Credential Binding (`UserAuthConfig`)](#7-biometric--device-credential-binding-userauthconfig)
  - [8. Kotlin Multiplatform Setup (Android, iOS & JVM)](#8-kotlin-multiplatform-setup-android-ios--jvm)
- [Publishing a Release from Your GitHub Repository](#publishing-a-release-from-your-github-repository)
- [FAQ & Best Practices](#faq--best-practices)
- [Sample App & Running Tests](#sample-app--running-tests)

---

## Why EncryptedDataStore?

- **Drop-in replacement for `EncryptedSharedPreferences`:** Reactive, type-safe `EncryptedPreferences` supporting `String`, `Int`, `Long`, `Float`, `Double`, `Boolean`, `Set<String>`, `ByteArray`, and `@Serializable` objects.
- **Envelope Encryption (KEK + DEK):**
  - **Android:** 256-bit AES-GCM master key in `AndroidKeyStore` (StrongBox on API 28+ with automatic fallback to TEE) wrapping a Google Tink DEK keyset (`AES256_GCM` or `XCHACHA20_POLY1305`).
  - **iOS:** 256-bit CSPRNG DEKs (`SecRandomCopyBytes`) stored in the iOS Keychain (`*ThisDeviceOnly`) with Apple native AES-GCM via `cryptography-provider-apple`.
  - **JVM:** Google Tink keyset wrapped with PBKDF2-HMAC-SHA256 (`310,000` iterations) when a passphrase provider is configured, or an isolated local AES-256-GCM KEK.
- **Authenticated Binary Envelope (`EDST` v1):** Binds the 14-byte header (magic, format version, cipher algorithm, key epoch), domain tag, `storeName`, and optional caller AAD (e.g., `userId`/`tenantId`) into the AEAD Associated Data to block file-swapping, truncation, and algorithm downgrade attacks.
- **Zero Cloud Backup Leaks by Default:** Stores encrypted files, keysets, and metadata in `noBackupFilesDir` (`0700`/`0600` permissions) on Android, and sets `NSURLIsExcludedFromBackupKey = true` on iOS.
- **Key Rotation & Secure Wipe:** Supports manual (`rotateKeys()`) and automatic (`KeyRotationPolicy.Automatic` by age or write count) key rotation, plus `clearAndReset()` which destroys historical keys.
- **R8 / ProGuard Ready:** Consumer keep rules (`consumer-rules.pro`) are automatically bundled in the AAR.

---

## Installation (Direct from GitHub)

Consumers can add `EncryptedDataStore` via Gradle without cloning this repository locally.

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
    implementation("com.github.Maignardi:encrypted-datastore:0.1.0")
}
```

**Kotlin Multiplatform (`shared/build.gradle.kts`):**
```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("com.github.Maignardi:encrypted-datastore:0.1.0")
        }
    }
}
```

### Option B: Version Catalog (`libs.versions.toml`)

```toml
[versions]
encryptedDatastore = "0.1.0"

[libraries]
encrypted-datastore = { module = "com.github.Maignardi:encrypted-datastore", version.ref = "encryptedDatastore" }
```

```kotlin
dependencies {
    implementation(libs.encrypted.datastore)
}
```

### Option C: GitHub Packages (Full KMP including iOS)

Tagging `v*` triggers [`.github/workflows/publish.yml`](.github/workflows/publish.yml) to publish Android, JVM, and iOS artifacts to GitHub Packages:

```kotlin
repositories {
    google()
    mavenCentral()
    maven {
        url = uri("https://maven.pkg.github.com/Maignardi/encrypted-datastore")
        credentials {
            username = providers.gradleProperty("gpr.user").orNull ?: System.getenv("GITHUB_ACTOR")
            password = providers.gradleProperty("gpr.key").orNull ?: System.getenv("GITHUB_TOKEN")
        }
    }
}

dependencies {
    implementation("io.github.maignardi:encrypted-datastore:0.1.0")
}
```

---

## Tutorials & Usage

### 1. Replacing `EncryptedSharedPreferences` (`EncryptedPreferences`)

Create **one singleton instance per `storeName`** (e.g., via Hilt, Koin, or an `Application`-scoped property), following Jetpack DataStore's single-instance rule:

```kotlin
import io.github.encrypteddatastore.*
import kotlin.time.Duration.Companion.days

val authPrefs: EncryptedPreferences = EncryptedDataStoreFactory.createPreferences(
    context = PlatformStorageContext(applicationContext),
    config = SecurityConfig(
        storeName = "auth_prefs",
        algorithm = CipherAlgorithm.AES256_GCM, // or CipherAlgorithm.XCHACHA20_POLY1305
        keyRotationPolicy = KeyRotationPolicy.Automatic(
            maxKeyAge = 90.days,
            maxWritesBeforeRotation = 100_000L,
            maxRetainedKeys = 2,
        ),
        recoveryPolicy = KeystoreRecoveryPolicy.STRICT,
    ),
)
```

Define type-safe keys and read/write atomically:

```kotlin
@Serializable
data class UserProfile(val id: Long, val email: String)

object AuthKeys {
    val accessToken = PreferenceKeys.string("access_token")
    val expiresAt = PreferenceKeys.long("expires_at")
    val loginCount = PreferenceKeys.int("login_count")
    val biometricEnabled = PreferenceKeys.boolean("biometric_enabled")
    val scopes = PreferenceKeys.stringSet("scopes")
    val deviceSeed = PreferenceKeys.byteArray("device_seed")
    val profile = PreferenceKeys.serializable("profile", UserProfile.serializer())
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

#### All Supported `PreferenceKeys` Builders

| Builder | Kotlin Type |
| --- | --- |
| `PreferenceKeys.string(name)` | `String` |
| `PreferenceKeys.int(name)` | `Int` |
| `PreferenceKeys.long(name)` | `Long` |
| `PreferenceKeys.float(name)` | `Float` |
| `PreferenceKeys.double(name)` | `Double` |
| `PreferenceKeys.boolean(name)` | `Boolean` |
| `PreferenceKeys.stringSet(name)` | `Set<String>` |
| `PreferenceKeys.byteArray(name)` | `ByteArray` |
| `PreferenceKeys.serializable(name, serializer)` | Any `@Serializable` type `T` |

---

### 2. Using `EncryptedPreferences` in Jetpack Compose

```kotlin
@Composable
fun TokenStatusBanner(prefs: EncryptedPreferences) {
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

See [`EncryptedVaultScreen.kt`](sample-android/src/main/kotlin/io/github/encrypteddatastore/sample/EncryptedVaultScreen.kt) for a full working Compose example.

---

### 3. Typed `@Serializable` Object Store (`EncryptedDataStore<T>`)

For structured domain models, use `EncryptedDataStoreFactory.create(...)`. You can also pass `associatedDataProvider` to cryptographically bind ciphertext to a user or tenant ID (preventing cross-account file replay):

```kotlin
@Serializable
data class SessionState(
    val accessToken: String = "",
    val refreshToken: String = "",
    val userId: String = "",
)

val sessionStore = EncryptedDataStoreFactory.create(
    context = PlatformStorageContext(applicationContext),
    config = SecurityConfig(
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

---

### 4. Migrating from Legacy `SharedPreferences` / `EncryptedSharedPreferences`

Upgrade existing users smoothly without losing saved tokens or settings. The source `SharedPreferences` is cleared **only after** the encrypted DataStore transaction commits:

```kotlin
// Works with plain SharedPreferences or deprecated androidx.security.crypto.EncryptedSharedPreferences
val report = authPrefs.migrateFromSharedPreferences(
    source = legacyEncryptedPrefs,
    clearSourceOnSuccess = true,
)

// Optional: migrate only specific keys
val partialReport = authPrefs.migrateFromSharedPreferences(
    source = legacyPrefs,
    keysToMigrate = setOf("access_token", "refresh_token"),
    clearSourceOnSuccess = true,
)
```

---

### 5. Choosing a `KeystoreRecoveryPolicy` (OEM Resilience)

Some Android OEMs suffer from `AndroidKeyStore` bugs (keys invalidated after OS updates or unavailable Keystore services). `EncryptedDataStore` never weakens security or wipes data silently — choose the policy that matches your threat model:

| Policy | Behavior on Keystore / File Corruption | Recommended For |
| --- | --- | --- |
| `KeystoreRecoveryPolicy.STRICT` *(Default)* | Fails closed by throwing `SecurityStorageException` (`KeystoreUnavailableException` / `StoreTamperedOrCorruptedException`). | High-security secrets, banking/payment tokens where silent resets are unacceptable. |
| `KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE` | Atomically wipes the corrupted keyset and store file, generates fresh keys, resets to default value, and calls `onRecovery`. | Session caches or tokens where the user can cleanly re-authenticate after OS Keystore corruption. |
| `KeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK` | Explicit opt-in for broken OEM Keystores: derives an app-scoped software KEK via HKDF-SHA256 over an installation-unique CSPRNG secret in `noBackupFilesDir`, and reports `SecurityLevel.SOFTWARE_FALLBACK` in `diagnostics()`. | Non-critical preferences or apps targeting devices with known broken hardware Keystores. |

```kotlin
val config = SecurityConfig(
    storeName = "resilient_session",
    recoveryPolicy = KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE,
    onRecovery = { event ->
        // Log redacted reason and prompt user to sign in again
        analytics.log("store_reset", mapOf("store" to event.storeName))
    },
    eventListener = { event ->
        // Redacted audit events (never contain keys or plaintext)
        when (event) {
            is SecurityEvent.StrongBoxFallbackToTee -> { /* StrongBox unavailable, TEE used */ }
            is SecurityEvent.KeyRotated -> { /* Key rotated from oldEpoch to newEpoch */ }
            is SecurityEvent.SoftwareFallbackActivated -> { /* Software fallback active */ }
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
val diag: SecurityDiagnostics = authPrefs.diagnostics()
// diag.securityLevel -> STRONGBOX / HARDWARE_TEE / KEYCHAIN / JVM_KEYSTORE / SOFTWARE_FALLBACK
// diag.hardwareBacked -> true / false
// diag.currentKeyEpoch -> 2
// diag.writesSinceRotation -> 0

// 3. Secure logout: overwrites store with default state AND destroys all prior DEKs
// Even an attacker holding an older disk snapshot cannot decrypt it afterward.
authPrefs.clearAndReset()
```

---

### 7. Biometric & Device Credential Binding (`UserAuthConfig`)

Bind the AndroidKeyStore master key to recent biometric or lockscreen authentication:

```kotlin
val biometricVault = EncryptedDataStoreFactory.createPreferences(
    context = PlatformStorageContext(applicationContext),
    config = SecurityConfig(
        storeName = "biometric_vault",
        userAuthConfig = UserAuthConfig(
            authValidityDurationSeconds = 30,
            allowDeviceCredential = true,
            invalidateOnBiometricEnrollment = true,
        ),
    ),
)
```

> **Important:** When the device is locked or the authentication window has expired, operations throw `UserAuthenticationRequiredException`. This transient lock state **never** triggers corruption recovery or store wiping — prompt `BiometricPrompt` and retry.

---

### 8. Kotlin Multiplatform Setup (Android, iOS & JVM)

Instantiate `PlatformStorageContext` per platform and share your store factory in `commonMain`:

```kotlin
// commonMain
class VaultRepository(context: PlatformStorageContext) {
    val prefs = EncryptedDataStoreFactory.createPreferences(
        context = context,
        config = SecurityConfig(
            storeName = "shared_vault",
            iosAccessibility = IosKeychainAccessibility.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
        ),
    )
}

// androidMain
VaultRepository(PlatformStorageContext(applicationContext))

// iosMain
VaultRepository(PlatformStorageContext())

// jvmMain (optionally protect the Tink keyset with a PBKDF2 passphrase)
VaultRepository(
    PlatformStorageContext(
        storageDirectory = File(System.getProperty("user.home"), ".myapp"),
        masterPassphraseProvider = { promptPassphrase() },
    )
)
```

---

## Publishing a Release from GitHub

1. Push changes to `Maignardi/encrypted-datastore`.
2. Create and push a version tag:
   ```bash
   git tag 0.1.0
   git push origin 0.1.0
   ```
3. **JitPack:** Anyone can immediately add `implementation("com.github.Maignardi:encrypted-datastore:0.1.0")` — JitPack reads [`jitpack.yml`](jitpack.yml), builds with JDK 21 + Android SDK 35, and publishes the Android, JVM, and KMP artifacts automatically.
4. **GitHub Packages:** Push a `v*` tag (e.g. `v0.1.0`) to trigger [`.github/workflows/publish.yml`](.github/workflows/publish.yml), publishing all targets including iOS.

---

## FAQ & Best Practices

- **Why do I get `IllegalStateException: There are multiple DataStores active for the same file`?**
  Jetpack DataStore requires a single active instance per file path per process. Create each `EncryptedDataStore` / `EncryptedPreferences` once as a singleton (Hilt `@Singleton`, Koin `single`, or `object` / `Application` property). In unit tests that reopen the same store path, call `suspend fun close()` before creating a new instance.
- **Do I need extra ProGuard / R8 rules?**
  No. [`consumer-rules.pro`](encrypted-datastore/consumer-rules.pro) is embedded inside the published AAR (`proguard.txt`) and applied automatically in release builds.
- **Are files excluded from Android Auto Backup?**
  Yes. By default, encrypted `.edst` payloads, `.keyset` files, and `.meta` files are stored in `context.noBackupFilesDir` with `0700`/`0600` POSIX permissions.

---

## Sample App & Running Tests

- [`sample-android`](sample-android) provides a Jetpack Compose Material 3 app (`EncryptedVaultScreen`) and Compose UI tests (`EncryptedVaultScreenTest`).
- Run the full verification suite:

```bash
./gradlew :encrypted-datastore:jvmTest :encrypted-datastore:testAndroidHostTest :sample-android:testDebugUnitTest
```

See [`SECURITY.md`](SECURITY.md) for the cryptographic specification, envelope layout, and threat model.
