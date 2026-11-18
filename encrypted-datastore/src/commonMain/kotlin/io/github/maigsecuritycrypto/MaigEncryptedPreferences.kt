package io.github.maigsecuritycrypto

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * A type-safe preference key for [MaigEncryptedPreferences].
 */
public sealed class MaigPreferenceKey<T>(public val name: String) {
    init {
        require(name.isNotBlank()) { "MaigPreferenceKey name must not be blank" }
    }

    internal abstract fun encode(value: T, json: Json): PreferenceEntry
    internal abstract fun decode(entry: PreferenceEntry, json: Json): T?
}

@Serializable
internal enum class PreferenceValueType {
    STRING,
    INT,
    LONG,
    FLOAT,
    DOUBLE,
    BOOLEAN,
    STRING_SET,
    BYTE_ARRAY,
    SERIALIZABLE,
}

@Serializable
internal data class PreferenceEntry(
    val type: PreferenceValueType,
    val stringValue: String? = null,
    val stringSetValue: Set<String>? = null,
)

@Serializable
internal data class EncryptedPreferencesState(
    val entries: Map<String, PreferenceEntry> = emptyMap(),
    val completedMigrations: Set<String> = emptySet(),
)

private class StringPreferenceKey(name: String) : MaigPreferenceKey<String>(name) {
    override fun encode(value: String, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.STRING, stringValue = value)

    override fun decode(entry: PreferenceEntry, json: Json): String? =
        if (entry.type == PreferenceValueType.STRING) entry.stringValue else null
}

private class IntPreferenceKey(name: String) : MaigPreferenceKey<Int>(name) {
    override fun encode(value: Int, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.INT, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Int? =
        if (entry.type == PreferenceValueType.INT) entry.stringValue?.toIntOrNull() else null
}

private class LongPreferenceKey(name: String) : MaigPreferenceKey<Long>(name) {
    override fun encode(value: Long, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.LONG, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Long? =
        if (entry.type == PreferenceValueType.LONG) entry.stringValue?.toLongOrNull() else null
}

private class FloatPreferenceKey(name: String) : MaigPreferenceKey<Float>(name) {
    override fun encode(value: Float, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.FLOAT, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Float? =
        if (entry.type == PreferenceValueType.FLOAT) entry.stringValue?.toFloatOrNull() else null
}

private class DoublePreferenceKey(name: String) : MaigPreferenceKey<Double>(name) {
    override fun encode(value: Double, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.DOUBLE, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Double? =
        if (entry.type == PreferenceValueType.DOUBLE) entry.stringValue?.toDoubleOrNull() else null
}

private class BooleanPreferenceKey(name: String) : MaigPreferenceKey<Boolean>(name) {
    override fun encode(value: Boolean, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.BOOLEAN, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Boolean? =
        if (entry.type == PreferenceValueType.BOOLEAN) entry.stringValue?.toBooleanStrictOrNull() else null
}

private class StringSetPreferenceKey(name: String) : MaigPreferenceKey<Set<String>>(name) {
    override fun encode(value: Set<String>, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.STRING_SET, stringSetValue = value.toSet())

    override fun decode(entry: PreferenceEntry, json: Json): Set<String>? =
        if (entry.type == PreferenceValueType.STRING_SET) entry.stringSetValue else null
}

@OptIn(ExperimentalEncodingApi::class)
private class ByteArrayPreferenceKey(name: String) : MaigPreferenceKey<ByteArray>(name) {
    override fun encode(value: ByteArray, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.BYTE_ARRAY, stringValue = Base64.encode(value))

    override fun decode(entry: PreferenceEntry, json: Json): ByteArray? =
        if (entry.type == PreferenceValueType.BYTE_ARRAY) {
            entry.stringValue?.let { Base64.decode(it) }
        } else {
            null
        }
}

private class SerializablePreferenceKey<T>(
    name: String,
    private val serializer: KSerializer<T>,
) : MaigPreferenceKey<T>(name) {
    override fun encode(value: T, json: Json): PreferenceEntry =
        PreferenceEntry(
            type = PreferenceValueType.SERIALIZABLE,
            stringValue = json.encodeToString(serializer, value),
        )

    override fun decode(entry: PreferenceEntry, json: Json): T? =
        if (entry.type == PreferenceValueType.SERIALIZABLE) {
            entry.stringValue?.let { json.decodeFromString(serializer, it) }
        } else {
            null
        }
}

public object MaigPreferenceKeys {
    public fun string(name: String): MaigPreferenceKey<String> = StringPreferenceKey(name)
    public fun int(name: String): MaigPreferenceKey<Int> = IntPreferenceKey(name)
    public fun long(name: String): MaigPreferenceKey<Long> = LongPreferenceKey(name)
    public fun float(name: String): MaigPreferenceKey<Float> = FloatPreferenceKey(name)
    public fun double(name: String): MaigPreferenceKey<Double> = DoublePreferenceKey(name)
    public fun boolean(name: String): MaigPreferenceKey<Boolean> = BooleanPreferenceKey(name)
    public fun stringSet(name: String): MaigPreferenceKey<Set<String>> = StringSetPreferenceKey(name)
    public fun byteArray(name: String): MaigPreferenceKey<ByteArray> = ByteArrayPreferenceKey(name)
    public fun <T> serializable(name: String, serializer: KSerializer<T>): MaigPreferenceKey<T> =
        SerializablePreferenceKey(name, serializer)
}

internal fun MaigEncryptedPreferencesSnapshot.hasCompletedMigration(migrationId: String): Boolean =
    migrationId in completedMigrations

/**
 * Immutable snapshot of decrypted preferences.
 */
public class MaigEncryptedPreferencesSnapshot internal constructor(
    private val entries: Map<String, PreferenceEntry>,
    private val json: Json,
    internal val completedMigrations: Set<String> = emptySet(),
) {
    public operator fun <T> get(key: MaigPreferenceKey<T>): T? {
        val entry = entries[key.name] ?: return null
        return key.decode(entry, json)
    }

    public fun contains(key: MaigPreferenceKey<*>): Boolean = entries.containsKey(key.name)

    public fun keys(): Set<String> = entries.keys.toSet()

    public fun isEmpty(): Boolean = entries.isEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MaigEncryptedPreferencesSnapshot) return false
        return entries == other.entries
    }

    override fun hashCode(): Int = entries.hashCode()
}

/**
 * Mutable builder used inside [MaigEncryptedPreferences.edit].
 */
public class MaigMutableEncryptedPreferences internal constructor(
    initialEntries: Map<String, PreferenceEntry>,
    private val json: Json,
    initialCompletedMigrations: Set<String> = emptySet(),
) {
    private val mutableEntries = initialEntries.toMutableMap()
    private val completedMigrations = initialCompletedMigrations.toMutableSet()

    internal fun markMigrationCompleted(migrationId: String) {
        completedMigrations += migrationId
    }

    public operator fun <T> get(key: MaigPreferenceKey<T>): T? {
        val entry = mutableEntries[key.name] ?: return null
        return key.decode(entry, json)
    }

    public operator fun <T> set(key: MaigPreferenceKey<T>, value: T?) {
        if (value == null) {
            mutableEntries.remove(key.name)
        } else {
            mutableEntries[key.name] = key.encode(value, json)
        }
    }

    public fun remove(key: MaigPreferenceKey<*>) {
        mutableEntries.remove(key.name)
    }

    public fun contains(key: MaigPreferenceKey<*>): Boolean = mutableEntries.containsKey(key.name)

    internal fun containsName(name: String): Boolean = mutableEntries.containsKey(name)

    public fun clear() {
        mutableEntries.clear()
    }

    internal fun toState(): EncryptedPreferencesState =
        EncryptedPreferencesState(
            entries = mutableEntries.toMap(),
            completedMigrations = completedMigrations.toSet(),
        )
}

/**
 * Migration hook executed atomically inside DataStore before any reads or writes are served.
 */
public interface MaigEncryptedPreferencesMigration {
    public suspend fun shouldMigrate(snapshot: MaigEncryptedPreferencesSnapshot): Boolean
    public suspend fun migrate(mutable: MaigMutableEncryptedPreferences)
    public suspend fun cleanUp() {}
}

/**
 * Modern, reactive, encrypted replacement for Android's deprecated `EncryptedSharedPreferences`.
 */
public class MaigEncryptedPreferences internal constructor(
    private val store: MaigEncryptedDataStore<EncryptedPreferencesState>,
    private val json: Json,
) {
    public val data: Flow<MaigEncryptedPreferencesSnapshot> = store.data
        .map { MaigEncryptedPreferencesSnapshot(it.entries, json, it.completedMigrations) }
        .distinctUntilChanged()

    public fun <T> observe(key: MaigPreferenceKey<T>): Flow<T?> =
        store.data
            .map { state -> state.entries[key.name] }
            .distinctUntilChanged()
            .map { entry -> entry?.let { key.decode(it, json) } }

    public suspend fun <T> get(key: MaigPreferenceKey<T>): T? = data.first()[key]

    public suspend fun contains(key: MaigPreferenceKey<*>): Boolean = data.first().contains(key)

    public suspend fun edit(transform: suspend (MaigMutableEncryptedPreferences) -> Unit): MaigEncryptedPreferencesSnapshot {
        val updated = store.updateData { state ->
            val mutable = MaigMutableEncryptedPreferences(state.entries, json, state.completedMigrations)
            transform(mutable)
            mutable.toState()
        }
        return MaigEncryptedPreferencesSnapshot(updated.entries, json, updated.completedMigrations)
    }

    public suspend fun rotateKeys(): Long = store.rotateKeys()

    public suspend fun clearAndReset() {
        store.clearAndReset { previous ->
            EncryptedPreferencesState(
                entries = emptyMap(),
                completedMigrations = previous.completedMigrations,
            )
        }
    }

    /**
     * Forcefully wipes the encrypted preferences file and key material without decrypting,
     * then closes this instance. Create a new instance via [MaigSecurityCrypto] afterward.
     */
    public suspend fun forceResetAndClose() {
        store.forceResetAndClose()
    }

    public suspend fun diagnostics(): MaigSecurityDiagnostics = store.diagnostics()

    /**
     * Releases this store's internal coroutine scope and active file lock.
     */
    public suspend fun close() {
        store.close()
    }
}
