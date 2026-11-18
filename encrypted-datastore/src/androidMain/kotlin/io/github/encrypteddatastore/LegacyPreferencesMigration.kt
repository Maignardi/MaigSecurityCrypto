package io.github.encrypteddatastore

import android.content.SharedPreferences

/**
 * Summary of a migration from legacy [SharedPreferences] / `EncryptedSharedPreferences`.
 */
public data class SharedPreferencesMigrationReport(
    public val migratedKeys: Int,
    public val skippedUnsupportedKeys: Set<String>,
    public val sourceCleared: Boolean,
)

/**
 * Atomically migrates entries from a legacy [SharedPreferences] (including deprecated
 * `androidx.security.crypto.EncryptedSharedPreferences`) into this [EncryptedPreferences].
 *
 * The source [SharedPreferences] is only cleared (when [clearSourceOnSuccess] is `true`)
 * after the encrypted DataStore commit completes successfully.
 */
public suspend fun EncryptedPreferences.migrateFromSharedPreferences(
    source: SharedPreferences,
    keysToMigrate: Set<String>? = null,
    clearSourceOnSuccess: Boolean = true,
): SharedPreferencesMigrationReport {
    val allEntries = source.all
    if (allEntries.isEmpty()) {
        return SharedPreferencesMigrationReport(
            migratedKeys = 0,
            skippedUnsupportedKeys = emptySet(),
            sourceCleared = false,
        )
    }

    val skipped = mutableSetOf<String>()
    var migratedCount = 0

    edit { prefs ->
        for ((key, value) in allEntries) {
            if (keysToMigrate != null && key !in keysToMigrate) continue
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
                        skipped += key
                    }
                }
                else -> skipped += key
            }
        }
    }

    var cleared = false
    if (clearSourceOnSuccess) {
        cleared = if (keysToMigrate == null) {
            source.edit().clear().commit()
        } else {
            source.edit().apply {
                keysToMigrate.forEach { remove(it) }
            }.commit()
        }
    }

    return SharedPreferencesMigrationReport(
        migratedKeys = migratedCount,
        skippedUnsupportedKeys = skipped.toSet(),
        sourceCleared = cleared,
    )
}
