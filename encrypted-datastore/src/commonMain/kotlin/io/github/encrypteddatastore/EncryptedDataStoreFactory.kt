package io.github.encrypteddatastore

import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.core.okio.OkioStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

/**
 * Factory for creating [EncryptedDataStore] and [EncryptedPreferences] instances.
 */
public object EncryptedDataStoreFactory {

    public val defaultJson: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    /**
     * Creates an [EncryptedDataStore] storing typed `@Serializable` state [T].
     */
    public fun <T> create(
        context: PlatformStorageContext,
        config: SecurityConfig,
        serializer: KSerializer<T>,
        defaultValue: () -> T,
        json: Json = defaultJson,
        scope: CoroutineScope = defaultIoCoroutineScope(),
    ): EncryptedDataStore<T> {
        val keyManager = createPlatformKeyManager(context, config)
        val (fileSystem, filePath) = resolveEncryptedStoreFile(context, config)
        val okioSerializer = EncryptedOkioSerializer(
            rawDefaultValue = defaultValue(),
            kSerializer = serializer,
            json = json,
            config = config,
            keyManager = keyManager,
        )
        val corruptionHandler = if (config.recoveryPolicy == KeystoreRecoveryPolicy.CLEAR_AND_REGENERATE) {
            ReplaceFileCorruptionHandler {
                val recoveredEpoch = okioSerializer.peekPendingRecoveryEpoch()
                EncryptedBox(value = defaultValue(), keyEpoch = recoveredEpoch)
            }
        } else {
            null
        }
        val storage = OkioStorage(
            fileSystem = fileSystem,
            serializer = okioSerializer,
            producePath = { filePath },
        )
        val storeScope = CoroutineScope(
            scope.coroutineContext + SupervisorJob(scope.coroutineContext[Job])
        )
        val internalStore = DataStoreFactory.create(
            storage = storage,
            corruptionHandler = corruptionHandler,
            scope = storeScope,
        )
        return EncryptedDataStore(
            internalStore = internalStore,
            keyManager = keyManager,
            config = config,
            fileSystem = fileSystem,
            filePath = filePath,
            storeScope = storeScope,
            defaultValueProvider = defaultValue,
        )
    }

    /**
     * Creates an [EncryptedPreferences] key-value store as a modern replacement for
     * `EncryptedSharedPreferences`.
     */
    public fun createPreferences(
        context: PlatformStorageContext,
        config: SecurityConfig,
        json: Json = defaultJson,
        scope: CoroutineScope = defaultIoCoroutineScope(),
    ): EncryptedPreferences {
        val store = create(
            context = context,
            config = config,
            serializer = EncryptedPreferencesState.serializer(),
            defaultValue = { EncryptedPreferencesState() },
            json = json,
            scope = scope,
        )
        return EncryptedPreferences(store = store, json = json)
    }
}
