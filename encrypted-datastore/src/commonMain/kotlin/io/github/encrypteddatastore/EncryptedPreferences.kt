package io.github.encrypteddatastore

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
 * A type-safe preference key for [EncryptedPreferences].
 */
public sealed class PreferenceKey<T>(public val name: String) {
    init {
        require(name.isNotBlank()) { "PreferenceKey name must not be blank" }
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
)

private class StringPreferenceKey(name: String) : PreferenceKey<String>(name) {
    override fun encode(value: String, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.STRING, stringValue = value)

    override fun decode(entry: PreferenceEntry, json: Json): String? =
        if (entry.type == PreferenceValueType.STRING) entry.stringValue else null
}

private class IntPreferenceKey(name: String) : PreferenceKey<Int>(name) {
    override fun encode(value: Int, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.INT, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Int? =
        if (entry.type == PreferenceValueType.INT) entry.stringValue?.toIntOrNull() else null
}

private class LongPreferenceKey(name: String) : PreferenceKey<Long>(name) {
    override fun encode(value: Long, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.LONG, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Long? =
        if (entry.type == PreferenceValueType.LONG) entry.stringValue?.toLongOrNull() else null
}

private class FloatPreferenceKey(name: String) : PreferenceKey<Float>(name) {
    override fun encode(value: Float, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.FLOAT, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Float? =
        if (entry.type == PreferenceValueType.FLOAT) entry.stringValue?.toFloatOrNull() else null
}

private class DoublePreferenceKey(name: String) : PreferenceKey<Double>(name) {
    override fun encode(value: Double, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.DOUBLE, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Double? =
        if (entry.type == PreferenceValueType.DOUBLE) entry.stringValue?.toDoubleOrNull() else null
}

private class BooleanPreferenceKey(name: String) : PreferenceKey<Boolean>(name) {
    override fun encode(value: Boolean, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.BOOLEAN, stringValue = value.toString())

    override fun decode(entry: PreferenceEntry, json: Json): Boolean? =
        if (entry.type == PreferenceValueType.BOOLEAN) entry.stringValue?.toBooleanStrictOrNull() else null
}

private class StringSetPreferenceKey(name: String) : PreferenceKey<Set<String>>(name) {
    override fun encode(value: Set<String>, json: Json): PreferenceEntry =
        PreferenceEntry(type = PreferenceValueType.STRING_SET, stringSetValue = value.toSet())

    override fun decode(entry: PreferenceEntry, json: Json): Set<String>? =
        if (entry.type == PreferenceValueType.STRING_SET) entry.stringSetValue else null
}

@OptIn(ExperimentalEncodingApi::class)
private class ByteArrayPreferenceKey(name: String) : PreferenceKey<ByteArray>(name) {
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
) : PreferenceKey<T>(name) {
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

public object PreferenceKeys {
    public fun string(name: String): PreferenceKey<String> = StringPreferenceKey(name)
    public fun int(name: String): PreferenceKey<Int> = IntPreferenceKey(name)
    public fun long(name: String): PreferenceKey<Long> = LongPreferenceKey(name)
    public fun float(name: String): PreferenceKey<Float> = FloatPreferenceKey(name)
    public fun double(name: String): PreferenceKey<Double> = DoublePreferenceKey(name)
    public fun boolean(name: String): PreferenceKey<Boolean> = BooleanPreferenceKey(name)
    public fun stringSet(name: String): PreferenceKey<Set<String>> = StringSetPreferenceKey(name)
    public fun byteArray(name: String): PreferenceKey<ByteArray> = ByteArrayPreferenceKey(name)
    public fun <T> serializable(name: String, serializer: KSerializer<T>): PreferenceKey<T> =
        SerializablePreferenceKey(name, serializer)
}

/**
 * Immutable snapshot of decrypted preferences.
 */
public class EncryptedPreferencesSnapshot internal constructor(
    private val entries: Map<String, PreferenceEntry>,
    private val json: Json,
) {
    public operator fun <T> get(key: PreferenceKey<T>): T? {
        val entry = entries[key.name] ?: return null
        return key.decode(entry, json)
    }

    public fun contains(key: PreferenceKey<*>): Boolean = entries.containsKey(key.name)

    public fun keys(): Set<String> = entries.keys.toSet()

    public fun isEmpty(): Boolean = entries.isEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedPreferencesSnapshot) return false
        return entries == other.entries
    }

    override fun hashCode(): Int = entries.hashCode()
}

/**
 * Mutable builder used inside [EncryptedPreferences.edit].
 */
public class MutableEncryptedPreferences internal constructor(
    initialEntries: Map<String, PreferenceEntry>,
    private val json: Json,
) {
    private val mutableEntries = initialEntries.toMutableMap()

    public operator fun <T> get(key: PreferenceKey<T>): T? {
        val entry = mutableEntries[key.name] ?: return null
        return key.decode(entry, json)
    }

    public operator fun <T> set(key: PreferenceKey<T>, value: T?) {
        if (value == null) {
            mutableEntries.remove(key.name)
        } else {
            mutableEntries[key.name] = key.encode(value, json)
        }
    }

    public fun remove(key: PreferenceKey<*>) {
        mutableEntries.remove(key.name)
    }

    public fun contains(key: PreferenceKey<*>): Boolean = mutableEntries.containsKey(key.name)

    internal fun containsName(name: String): Boolean = mutableEntries.containsKey(name)

    public fun clear() {
        mutableEntries.clear()
    }

    internal fun toState(): EncryptedPreferencesState =
        EncryptedPreferencesState(entries = mutableEntries.toMap())
}

/**
 * Migration hook executed atomically inside DataStore before any reads or writes are served.
 */
public interface EncryptedPreferencesMigration {
    public suspend fun shouldMigrate(snapshot: EncryptedPreferencesSnapshot): Boolean
    public suspend fun migrate(mutable: MutableEncryptedPreferences)
    public suspend fun cleanUp() {}
}

/**
 * Modern, reactive, encrypted replacement for Android's deprecated `EncryptedSharedPreferences`.
 */
public class EncryptedPreferences internal constructor(
    private val store: EncryptedDataStore<EncryptedPreferencesState>,
    private val json: Json,
) {
    public val data: Flow<EncryptedPreferencesSnapshot> = store.data
        .map { EncryptedPreferencesSnapshot(it.entries, json) }
        .distinctUntilChanged()

    public fun <T> observe(key: PreferenceKey<T>): Flow<T?> =
        store.data
            .map { state -> state.entries[key.name] }
            .distinctUntilChanged()
            .map { entry -> entry?.let { key.decode(it, json) } }

    public suspend fun <T> get(key: PreferenceKey<T>): T? = data.first()[key]

    public suspend fun contains(key: PreferenceKey<*>): Boolean = data.first().contains(key)

    public suspend fun edit(transform: suspend (MutableEncryptedPreferences) -> Unit): EncryptedPreferencesSnapshot {
        val updated = store.updateData { state ->
            val mutable = MutableEncryptedPreferences(state.entries, json)
            transform(mutable)
            mutable.toState()
        }
        return EncryptedPreferencesSnapshot(updated.entries, json)
    }

    public suspend fun rotateKeys(): Long = store.rotateKeys()

    public suspend fun clearAndReset() {
        store.clearAndReset()
    }

    /**
     * Forcefully wipes the encrypted preferences file and key material without decrypting,
     * then closes this instance. Create a new instance via [EncryptedDataStoreFactory] afterward.
     */
    public suspend fun forceResetAndClose() {
        store.forceResetAndClose()
    }

    public suspend fun diagnostics(): SecurityDiagnostics = store.diagnostics()

    /**
     * Releases this store's internal coroutine scope and active file lock.
     */
    public suspend fun close() {
        store.close()
    }
}
