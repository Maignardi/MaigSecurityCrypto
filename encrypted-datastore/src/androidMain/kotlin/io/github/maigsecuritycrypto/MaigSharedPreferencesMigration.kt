package io.github.maigsecuritycrypto

import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Summary of a migration from legacy [SharedPreferences] / `EncryptedSharedPreferences`.
 */
public data class MaigSharedPreferencesMigrationReport(
    public val migratedKeys: Int,
    public val skippedUnsupportedKeys: Set<String>,
    public val skippedExistingKeys: Set<String>,
    public val sourceCleared: Boolean,
)

/**
 * DataStore-integrated [MaigEncryptedPreferencesMigration] that runs atomically before any reads or
 * writes are served when passed to [MaigSecurityCrypto.createPreferences].
 *
 * @param migrationId Unique identifier for this migration source (for example, `"legacy_auth_prefs"`).
 * Using a distinct [migrationId] per [SharedPreferences] source prevents collisions when multiple
 * sources migrate into the same [MaigEncryptedPreferences].
 */
public class MaigSharedPreferencesDataMigration(
    private val source: SharedPreferences,
    private val migrationId: String,
    private val keysToMigrate: Set<String>? = null,
    private val clearSourceOnSuccess: Boolean = true,
    private val overwriteExisting: Boolean = false,
) : MaigEncryptedPreferencesMigration {

    init {
        require(migrationId.isNotBlank()) { "migrationId must not be blank" }
    }

    override suspend fun shouldMigrate(snapshot: MaigEncryptedPreferencesSnapshot): Boolean {
        if (snapshot.hasCompletedMigration(migrationId)) return false
        val entries = withContext(Dispatchers.IO) { source.all }
        if (entries.isEmpty()) return false
        return entries.keys.any { key ->
            (keysToMigrate == null || key in keysToMigrate) &&
                (overwriteExisting || !snapshot.containsName(key))
        }
    }

    override suspend fun migrate(mutable: MaigMutableEncryptedPreferences) {
        val allEntries = withContext(Dispatchers.IO) { source.all }
        for ((key, value) in allEntries) {
            if (keysToMigrate != null && key !in keysToMigrate) continue
            if (!overwriteExisting && mutable.containsName(key)) continue
            when (value) {
                is String -> mutable[MaigPreferenceKeys.string(key)] = value
                is Int -> mutable[MaigPreferenceKeys.int(key)] = value
                is Long -> mutable[MaigPreferenceKeys.long(key)] = value
                is Float -> mutable[MaigPreferenceKeys.float(key)] = value
                is Boolean -> mutable[MaigPreferenceKeys.boolean(key)] = value
                is Set<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    if (value.all { it is String }) {
                        mutable[MaigPreferenceKeys.stringSet(key)] = (value as Set<String>).toSet()
                    }
                }
            }
        }
        mutable.markMigrationCompleted(migrationId)
    }

    override suspend fun cleanUp() {
        if (!clearSourceOnSuccess) return
        withContext(Dispatchers.IO) {
            if (keysToMigrate == null) {
                source.edit().clear().commit()
            } else {
                source.edit().apply {
                    keysToMigrate.forEach { remove(it) }
                }.commit()
            }
        }
    }

    private fun MaigEncryptedPreferencesSnapshot.containsName(name: String): Boolean =
        name in keys()
}

/**
 * Migrates entries from a legacy [SharedPreferences] (including deprecated
 * `androidx.security.crypto.EncryptedSharedPreferences`) into this [MaigEncryptedPreferences].
 *
 * Disk I/O on [source] executes on [Dispatchers.IO].
 * By default ([overwriteExisting] = `false`), keys that already exist in [MaigEncryptedPreferences]
 * are preserved so repeated invocations remain idempotent even if [clearSourceOnSuccess] is `false`.
 */
public suspend fun MaigEncryptedPreferences.migrateFromSharedPreferences(
    source: SharedPreferences,
    keysToMigrate: Set<String>? = null,
    clearSourceOnSuccess: Boolean = true,
    overwriteExisting: Boolean = false,
): MaigSharedPreferencesMigrationReport {
    val allEntries = withContext(Dispatchers.IO) { source.all }
    if (allEntries.isEmpty()) {
        return MaigSharedPreferencesMigrationReport(
            migratedKeys = 0,
            skippedUnsupportedKeys = emptySet(),
            skippedExistingKeys = emptySet(),
            sourceCleared = false,
        )
    }

    val skippedUnsupported = mutableSetOf<String>()
    val skippedExisting = mutableSetOf<String>()
    var migratedCount = 0

    edit { prefs ->
        for ((key, value) in allEntries) {
            if (keysToMigrate != null && key !in keysToMigrate) continue
            if (!overwriteExisting && prefs.containsName(key)) {
                skippedExisting += key
                continue
            }
            when (value) {
                is String -> {
                    prefs[MaigPreferenceKeys.string(key)] = value
                    migratedCount++
                }
                is Int -> {
                    prefs[MaigPreferenceKeys.int(key)] = value
                    migratedCount++
                }
                is Long -> {
                    prefs[MaigPreferenceKeys.long(key)] = value
                    migratedCount++
                }
                is Float -> {
                    prefs[MaigPreferenceKeys.float(key)] = value
                    migratedCount++
                }
                is Boolean -> {
                    prefs[MaigPreferenceKeys.boolean(key)] = value
                    migratedCount++
                }
                is Set<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    if (value.all { it is String }) {
                        prefs[MaigPreferenceKeys.stringSet(key)] = (value as Set<String>).toSet()
                        migratedCount++
                    } else {
                        skippedUnsupported += key
                    }
                }
                else -> skippedUnsupported += key
            }
        }
    }

    var cleared = false
    if (clearSourceOnSuccess) {
        cleared = withContext(Dispatchers.IO) {
            if (keysToMigrate == null) {
                source.edit().clear().commit()
            } else {
                source.edit().apply {
                    keysToMigrate.forEach { remove(it) }
                }.commit()
            }
        }
    }

    return MaigSharedPreferencesMigrationReport(
        migratedKeys = migratedCount,
        skippedUnsupportedKeys = skippedUnsupported.toSet(),
        skippedExistingKeys = skippedExisting.toSet(),
        sourceCleared = cleared,
    )
}
