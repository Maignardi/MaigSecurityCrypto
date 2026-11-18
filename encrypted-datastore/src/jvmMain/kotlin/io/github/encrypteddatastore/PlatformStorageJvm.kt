package io.github.encrypteddatastore

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import okio.FileSystem
import okio.Path
import java.io.File

public actual class PlatformStorageContext(
    public val storageDirectory: Path,
    public val fileSystem: FileSystem = FileSystem.SYSTEM,
    internal val masterPassphraseProvider: (() -> CharArray)? = null,
) {
    public constructor(
        storageDirectory: File,
        masterPassphraseProvider: (() -> CharArray)? = null,
    ) : this(
        storageDirectory = with(Path.Companion) { storageDirectory.toOkioPath() },
        fileSystem = FileSystem.SYSTEM,
        masterPassphraseProvider = masterPassphraseProvider,
    )
}

internal actual fun resolveEncryptedStoreFile(
    context: PlatformStorageContext,
    config: SecurityConfig,
): Pair<FileSystem, Path> {
    val storeDir = context.storageDirectory / "encrypted_datastore"
    context.fileSystem.createDirectories(storeDir)
    enforceRestrictiveDirPermissions(storeDir)
    val storeFile = storeDir / "${config.storeName}.edst"
    return context.fileSystem to storeFile
}

internal actual fun enforceRestrictiveFilePermissions(
    fileSystem: FileSystem,
    path: Path,
) {
    if (fileSystem !== FileSystem.SYSTEM) return
    val file = path.toFile()
    if (!file.exists()) return
    file.setReadable(false, false)
    file.setReadable(true, true)
    file.setWritable(false, false)
    file.setWritable(true, true)
    file.setExecutable(false, false)
}

internal fun enforceRestrictiveDirPermissions(path: Path) {
    val dir = path.toFile()
    if (!dir.exists()) return
    dir.setReadable(false, false)
    dir.setReadable(true, true)
    dir.setWritable(false, false)
    dir.setWritable(true, true)
    dir.setExecutable(false, false)
    dir.setExecutable(true, true)
}

internal actual fun defaultIoCoroutineScope(): CoroutineScope =
    CoroutineScope(SupervisorJob() + Dispatchers.IO)

internal actual fun createPlatformKeyManager(
    context: PlatformStorageContext,
    config: SecurityConfig,
): KeyManager = JvmTinkKeyManager(context, config)
