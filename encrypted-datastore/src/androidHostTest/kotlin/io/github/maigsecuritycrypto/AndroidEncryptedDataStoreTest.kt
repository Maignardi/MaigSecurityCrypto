package io.github.maigsecuritycrypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidEncryptedDataStoreTest {

    private fun context(): Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `stores encrypted files inside noBackupFilesDir`() {
        val ctx = context()
        val storageCtx = MaigStorageContext(ctx)
        val (_, path) = resolveEncryptedStoreFile(
            storageCtx,
            MaigSecurityConfig(storeName = "auth_store"),
        )
        val file = File(path.toString())
        assertTrue(
            file.absolutePath.startsWith(ctx.noBackupFilesDir.absolutePath),
            "Expected store file in noBackupFilesDir, got: ${file.absolutePath}",
        )
    }

    @Test
    fun `STRICT policy fails closed when AndroidKeyStore is unavailable`() = runTest {
        val storageCtx = MaigStorageContext(context())
        val prefs = MaigSecurityCrypto.createPreferences(
            context = storageCtx,
            config = MaigSecurityConfig(
                storeName = "strict_robolectric",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.STRICT,
            ),
        )
        // Robolectric has no AndroidKeyStore provider by default: MUST fail closed, never downgrade!
        assertFailsWith<MaigKeystoreUnavailableException> {
            prefs.edit { it[MaigPreferenceKeys.string("k")] = "v" }
        }
        prefs.close()
    }

    @Test
    fun `EXPLICIT_SOFTWARE_FALLBACK survives missing OEM Keystore and migrates SharedPreferences`() = runTest {
        val ctx = context()
        val events = mutableListOf<MaigSecurityEvent>()
        val legacyPrefs = ctx.getSharedPreferences("legacy_prefs", Context.MODE_PRIVATE)
        legacyPrefs.edit()
            .putString("auth_token", "legacy_jwt_123")
            .putInt("login_count", 5)
            .putLong("last_sync", 1_700_000_000L)
            .putFloat("score", 9.5f)
            .putBoolean("onboarding_done", true)
            .putStringSet("roles", setOf("user", "beta"))
            .commit()

        val encryptedPrefs = MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(ctx),
            config = MaigSecurityConfig(
                storeName = "migrated_prefs",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
                eventListener = { events += it },
            ),
        )

        val report = encryptedPrefs.migrateFromSharedPreferences(legacyPrefs)
        assertEquals(6, report.migratedKeys)
        assertTrue(report.skippedUnsupportedKeys.isEmpty())
        assertTrue(report.sourceCleared)
        assertTrue(legacyPrefs.all.isEmpty())

        assertEquals("legacy_jwt_123", encryptedPrefs.get(MaigPreferenceKeys.string("auth_token")))
        assertEquals(5, encryptedPrefs.get(MaigPreferenceKeys.int("login_count")))
        assertEquals(1_700_000_000L, encryptedPrefs.get(MaigPreferenceKeys.long("last_sync")))
        assertEquals(9.5f, encryptedPrefs.get(MaigPreferenceKeys.float("score")))
        assertEquals(true, encryptedPrefs.get(MaigPreferenceKeys.boolean("onboarding_done")))
        assertEquals(setOf("user", "beta"), encryptedPrefs.get(MaigPreferenceKeys.stringSet("roles")))

        val diag = encryptedPrefs.diagnostics()
        assertEquals(MaigSecurityLevel.SOFTWARE_FALLBACK, diag.securityLevel)
        assertFalse(diag.hardwareBacked)
        assertTrue(events.any { it is MaigSecurityEvent.SoftwareFallbackActivated })
        encryptedPrefs.close()
    }

    @Test
    fun `selective SharedPreferences migration preserves unselected keys when configured`() = runTest {
        val ctx = context()
        val legacyPrefs = ctx.getSharedPreferences("selective_legacy", Context.MODE_PRIVATE)
        legacyPrefs.edit()
            .putString("keep_me", "yes")
            .putString("move_me", "secret_value")
            .commit()

        val encryptedPrefs = MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(ctx),
            config = MaigSecurityConfig(
                storeName = "selective_migrated",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
            ),
        )

        val report = encryptedPrefs.migrateFromSharedPreferences(
            source = legacyPrefs,
            keysToMigrate = setOf("move_me"),
            clearSourceOnSuccess = true,
        )

        assertEquals(1, report.migratedKeys)
        assertTrue(report.sourceCleared)
        assertEquals("secret_value", encryptedPrefs.get(MaigPreferenceKeys.string("move_me")))
        assertNull(encryptedPrefs.get(MaigPreferenceKeys.string("keep_me")))
        assertEquals("yes", legacyPrefs.getString("keep_me", null))
        assertNull(legacyPrefs.getString("move_me", null))
        encryptedPrefs.close()
    }

    @Test
    fun `SharedPreferences migration is idempotent when clearSourceOnSuccess is false`() = runTest {
        val ctx = context()
        val legacyPrefs = ctx.getSharedPreferences("idempotent_legacy", Context.MODE_PRIVATE)
        legacyPrefs.edit()
            .putString("token", "old_token")
            .putInt("version", 1)
            .commit()

        val encryptedPrefs = MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(ctx),
            config = MaigSecurityConfig(
                storeName = "idempotent_target",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
            ),
        )

        val first = encryptedPrefs.migrateFromSharedPreferences(
            source = legacyPrefs,
            clearSourceOnSuccess = false,
        )
        assertEquals(2, first.migratedKeys)
        assertFalse(first.sourceCleared)

        // App updates token in MaigEncryptedPreferences
        val tokenKey = MaigPreferenceKeys.string("token")
        encryptedPrefs.edit { it[tokenKey] = "newer_token" }

        // Running migration again must NOT overwrite newer_token with old_token
        val second = encryptedPrefs.migrateFromSharedPreferences(
            source = legacyPrefs,
            clearSourceOnSuccess = false,
        )
        assertEquals(0, second.migratedKeys)
        assertEquals(setOf("token", "version"), second.skippedExistingKeys)
        assertEquals("newer_token", encryptedPrefs.get(tokenKey))
        encryptedPrefs.close()
    }

    @Test
    fun `software fallback supports key rotation tamper recovery and clearAndReset on Android`() = runTest {
        val ctx = context()
        val storageCtx = MaigStorageContext(ctx)
        val prefs = MaigSecurityCrypto.createPreferences(
            context = storageCtx,
            config = MaigSecurityConfig(
                storeName = "android_sw_lifecycle",
                algorithm = MaigCipherAlgorithm.XCHACHA20_POLY1305,
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
            ),
        )

        val secretKey = MaigPreferenceKeys.string("api_secret")
        prefs.edit { it[secretKey] = "android_secret_abc" }
        assertEquals(1L, prefs.diagnostics().currentKeyEpoch)

        val epoch2 = prefs.rotateKeys()
        assertEquals(2L, epoch2)
        assertEquals("android_secret_abc", prefs.get(secretKey))

        // Verify raw file hides plaintext
        val (_, storePath) = resolveEncryptedStoreFile(
            storageCtx,
            MaigSecurityConfig(storeName = "android_sw_lifecycle"),
        )
        val diskBytes = File(storePath.toString()).readBytes()
        assertFalse(diskBytes.decodeToString().contains("android_secret_abc"))

        prefs.clearAndReset()
        assertNull(prefs.get(secretKey))
        prefs.close()
    }

    @Test
    fun `master key alias is deterministically scoped to package and store name`() {
        val a1 = AndroidKeyStoreAead.buildAlias("com.example.app", "tokens")
        val a2 = AndroidKeyStoreAead.buildAlias("com.example.app", "cache")
        val a3 = AndroidKeyStoreAead.buildAlias("com.other.app", "tokens")
        assertTrue(a1.startsWith("edst_mk_"))
        assertTrue(a1 != a2)
        assertTrue(a1 != a3)
    }

    @Test
    @Config(sdk = [23])
    fun `writes and rotates cleanly on Android API 23 without java nio API 26 calls`() = runTest {
        val ctx = context()
        val prefs = MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(ctx),
            config = MaigSecurityConfig(
                storeName = "api23_compat",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
            ),
        )
        val key = MaigPreferenceKeys.string("k23")
        prefs.edit { it[key] = "hello_api23" }
        assertEquals(2L, prefs.rotateKeys())
        assertEquals("hello_api23", prefs.get(key))
        prefs.close()
    }

    @Test
    fun `MaigSharedPreferencesDataMigration runs automatically before first read`() = runTest {
        val ctx = context()
        val legacyPrefs = ctx.getSharedPreferences("auto_data_migration_legacy", Context.MODE_PRIVATE)
        legacyPrefs.edit()
            .putString("session_jwt", "auto_migrated_jwt")
            .putBoolean("remember_me", true)
            .commit()

        val prefs = MaigSecurityCrypto.createPreferences(
            context = MaigStorageContext(ctx),
            config = MaigSecurityConfig(
                storeName = "auto_data_migration_target",
                recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
            ),
            migrations = listOf(
                MaigSharedPreferencesDataMigration(
                    source = legacyPrefs,
                    migrationId = "auto_data_migration_legacy",
                )
            ),
        )

        // First read must already contain migrated values without any manual migration call
        assertEquals("auto_migrated_jwt", prefs.get(MaigPreferenceKeys.string("session_jwt")))
        assertEquals(true, prefs.get(MaigPreferenceKeys.boolean("remember_me")))
        assertTrue(legacyPrefs.all.isEmpty())
        prefs.close()
    }

    @Test
    fun `MaigSharedPreferencesDataMigration with overwriteExisting and clearSource false runs only once and survives clearAndReset`() = runTest {
        val ctx = context()
        val legacyPrefs = ctx.getSharedPreferences("once_legacy_prefs", Context.MODE_PRIVATE)
        legacyPrefs.edit().putString("token", "legacy_v1").commit()

        val config = MaigSecurityConfig(
            storeName = "once_migration_target",
            recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
        )
        val storageCtx = MaigStorageContext(ctx)

        val prefs1 = MaigSecurityCrypto.createPreferences(
            context = storageCtx,
            config = config,
            migrations = listOf(
                MaigSharedPreferencesDataMigration(
                    source = legacyPrefs,
                    migrationId = "legacy_v1_import",
                    clearSourceOnSuccess = false,
                    overwriteExisting = true,
                )
            ),
        )
        val tokenKey = MaigPreferenceKeys.string("token")
        assertEquals("legacy_v1", prefs1.get(tokenKey))
        prefs1.edit { it[tokenKey] = "new_app_token" }
        prefs1.close()

        // Reopen with same migration config: must NOT overwrite "new_app_token" with "legacy_v1"
        val prefs2 = MaigSecurityCrypto.createPreferences(
            context = storageCtx,
            config = config,
            migrations = listOf(
                MaigSharedPreferencesDataMigration(
                    source = legacyPrefs,
                    migrationId = "legacy_v1_import",
                    clearSourceOnSuccess = false,
                    overwriteExisting = true,
                )
            ),
        )
        assertEquals("new_app_token", prefs2.get(tokenKey))

        // Logout wipe via clearAndReset() must clear entries while preserving completedMigrations
        prefs2.clearAndReset()
        assertNull(prefs2.get(tokenKey))
        prefs2.close()

        // Reopen after logout: legacy_v1 must NOT resurrect!
        val prefs3 = MaigSecurityCrypto.createPreferences(
            context = storageCtx,
            config = config,
            migrations = listOf(
                MaigSharedPreferencesDataMigration(
                    source = legacyPrefs,
                    migrationId = "legacy_v1_import",
                    clearSourceOnSuccess = false,
                    overwriteExisting = true,
                )
            ),
        )
        assertNull(prefs3.get(tokenKey))
        prefs3.close()
    }

    @Test
    fun `forceResetAndClose wipes corrupted Android store under STRICT policy`() = runTest {
        val ctx = context()
        val storageCtx = MaigStorageContext(ctx)
        val config = MaigSecurityConfig(
            storeName = "android_force_reset",
            recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
        )
        val prefs = MaigSecurityCrypto.createPreferences(context = storageCtx, config = config)
        prefs.edit { it[MaigPreferenceKeys.string("k")] = "v" }
        prefs.close()

        val (_, storePath) = resolveEncryptedStoreFile(storageCtx, config)
        File(storePath.toString()).writeBytes("tampered_data".encodeToByteArray())

        val broken = MaigSecurityCrypto.createPreferences(context = storageCtx, config = config)
        assertFailsWith<MaigStoreTamperedOrCorruptedException> {
            broken.get(MaigPreferenceKeys.string("k"))
        }
        broken.forceResetAndClose()

        val fresh = MaigSecurityCrypto.createPreferences(context = storageCtx, config = config)
        assertNull(fresh.get(MaigPreferenceKeys.string("k")))
        fresh.close()
    }
}
