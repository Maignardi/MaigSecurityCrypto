package io.github.maigsecuritycrypto

import androidx.datastore.core.DataMigration
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.core.okio.OkioStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

/**
 * Factory for creating [MaigEncryptedDataStore] and [MaigEncryptedPreferences] instances.
 */
public object MaigSecurityCrypto {

    public val defaultJson: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    /**
     * Creates an [MaigEncryptedDataStore] storing typed `@Serializable` state [T].
     */
    public fun <T> create(
        context: MaigStorageContext,
        config: MaigSecurityConfig,
        serializer: KSerializer<T>,
        defaultValue: () -> T,
        json: Json = defaultJson,
        migrations: List<DataMigration<T>> = emptyList(),
        scope: CoroutineScope = defaultIoCoroutineScope(),
    ): MaigEncryptedDataStore<T> {
        val keyManager = createPlatformKeyManager(context, config)
        val (fileSystem, filePath) = resolveEncryptedStoreFile(context, config)
        val okioSerializer = EncryptedOkioSerializer(
            rawDefaultValue = defaultValue(),
            kSerializer = serializer,
            json = json,
            config = config,
            keyManager = keyManager,
        )
        val corruptionHandler = if (config.recoveryPolicy == MaigKeystoreRecoveryPolicy.CLEAR_AND_REGENERATE) {
            ReplaceFileCorruptionHandler {
                val recoveredEpoch = okioSerializer.peekPendingRecoveryEpoch()
                EncryptedBox(value = defaultValue(), keyEpoch = recoveredEpoch)
            }
        } else {
            null
        }
        val boxMigrations = migrations.map { userMigration ->
            object : DataMigration<EncryptedBox<T>> {
                override suspend fun shouldMigrate(currentData: EncryptedBox<T>): Boolean =
                    userMigration.shouldMigrate(currentData.value)

                override suspend fun migrate(currentData: EncryptedBox<T>): EncryptedBox<T> =
                    currentData.copy(value = userMigration.migrate(currentData.value))

                override suspend fun cleanUp() = userMigration.cleanUp()
            }
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
            migrations = boxMigrations,
            scope = storeScope,
        )
        return MaigEncryptedDataStore(
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
     * Creates an [MaigEncryptedPreferences] key-value store as a modern replacement for
     * `EncryptedSharedPreferences`.
     */
    public fun createPreferences(
        context: MaigStorageContext,
        config: MaigSecurityConfig,
        json: Json = defaultJson,
        migrations: List<MaigEncryptedPreferencesMigration> = emptyList(),
        scope: CoroutineScope = defaultIoCoroutineScope(),
    ): MaigEncryptedPreferences {
        val dataMigrations = migrations.map { prefMigration ->
            object : DataMigration<EncryptedPreferencesState> {
                override suspend fun shouldMigrate(currentData: EncryptedPreferencesState): Boolean =
                    prefMigration.shouldMigrate(
                        MaigEncryptedPreferencesSnapshot(
                            entries = currentData.entries,
                            json = json,
                            completedMigrations = currentData.completedMigrations,
                        )
                    )

                override suspend fun migrate(currentData: EncryptedPreferencesState): EncryptedPreferencesState {
                    val mutable = MaigMutableEncryptedPreferences(
                        initialEntries = currentData.entries,
                        json = json,
                        initialCompletedMigrations = currentData.completedMigrations,
                    )
                    prefMigration.migrate(mutable)
                    return mutable.toState()
                }

                override suspend fun cleanUp() = prefMigration.cleanUp()
            }
        }
        val store = create(
            context = context,
            config = config,
            serializer = EncryptedPreferencesState.serializer(),
            defaultValue = { EncryptedPreferencesState() },
            json = json,
            migrations = dataMigrations,
            scope = scope,
        )
        return MaigEncryptedPreferences(store = store, json = json)
    }
}
