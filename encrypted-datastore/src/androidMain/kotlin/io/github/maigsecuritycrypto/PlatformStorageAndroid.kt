package io.github.maigsecuritycrypto

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import okio.FileSystem
import okio.Path
import okio.Path.Companion.toOkioPath
import java.io.File

public actual class MaigStorageContext(
    context: Context,
) {
    public val applicationContext: Context = context.applicationContext
}

internal fun resolveAndroidStoreDirectory(context: MaigStorageContext): File {
    val storeDir = File(context.applicationContext.noBackupFilesDir, "encrypted_datastore")
    if (!storeDir.exists()) {
        storeDir.mkdirs()
    }
    enforceRestrictiveDirPermissions(storeDir)
    return storeDir
}

internal actual fun resolveEncryptedStoreFile(
    context: MaigStorageContext,
    config: MaigSecurityConfig,
): Pair<FileSystem, Path> {
    val storeDir = resolveAndroidStoreDirectory(context)
    val storeFile = File(storeDir, "${config.storeName}.edst")
    return FileSystem.SYSTEM to storeFile.toOkioPath()
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

internal fun enforceRestrictiveDirPermissions(dir: File) {
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

internal actual fun defaultCipherAlgorithm(): MaigCipherAlgorithm = MaigCipherAlgorithm.AES256_GCM

internal actual fun createPlatformKeyManager(
    context: MaigStorageContext,
    config: MaigSecurityConfig,
): KeyManager = AndroidTinkKeyManager(context, config)
