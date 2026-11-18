package io.github.encrypteddatastore

import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Summary of a migration from legacy [SharedPreferences] / `EncryptedSharedPreferences`.
 */
public data class SharedPreferencesMigrationReport(
    public val migratedKeys: Int,
    public val skippedUnsupportedKeys: Set<String>,
    public val skippedExistingKeys: Set<String>,
    public val sourceCleared: Boolean,
)

/**
 * Migrates entries from a legacy [SharedPreferences] (including deprecated
 * `androidx.security.crypto.EncryptedSharedPreferences`) into this [EncryptedPreferences].
 *
 * Disk I/O on [source] executes on [Dispatchers.IO].
 * By default ([overwriteExisting] = `false`), keys that already exist in [EncryptedPreferences]
 * are preserved so repeated invocations remain idempotent even if [clearSourceOnSuccess] is `false`.
 */
public suspend fun EncryptedPreferences.migrateFromSharedPreferences(
    source: SharedPreferences,
    keysToMigrate: Set<String>? = null,
    clearSourceOnSuccess: Boolean = true,
    overwriteExisting: Boolean = false,
): SharedPreferencesMigrationReport {
    val allEntries = withContext(Dispatchers.IO) { source.all }
    if (allEntries.isEmpty()) {
        return SharedPreferencesMigrationReport(
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
                    prefs[PreferenceKeys.string(key)] = value
                    migratedCount++
                }
                is Int -> {
                    prefs[PreferenceKeys.int(key)] = value
                    migratedCount++
                }
                is Long -> {
                    prefs[PreferenceKeys.long(key)] = value
                    migratedCount++
                }
                is Float -> {
                    prefs[PreferenceKeys.float(key)] = value
                    migratedCount++
                }
                is Boolean -> {
                    prefs[PreferenceKeys.boolean(key)] = value
                    migratedCount++
                }
                is Set<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    if (value.all { it is String }) {
                        prefs[PreferenceKeys.stringSet(key)] = (value as Set<String>).toSet()
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

    return SharedPreferencesMigrationReport(
        migratedKeys = migratedCount,
        skippedUnsupportedKeys = skippedUnsupported.toSet(),
        skippedExistingKeys = skippedExisting.toSet(),
        sourceCleared = cleared,
    )
}
