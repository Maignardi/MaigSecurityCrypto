@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.github.encrypteddatastore

import kotlinx.cinterop.toKString
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.SupervisorJob
import okio.FileSystem
import okio.Path
import okio.Path.Companion.toPath
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSBundle
import platform.Foundation.NSFileManager
import platform.Foundation.NSURL
import platform.Foundation.NSURLIsExcludedFromBackupKey
import platform.Foundation.NSUserDomainMask
import platform.posix.chmod

public actual class PlatformStorageContext(
    public val directoryPath: String? = null,
    public val keychainService: String? = null,
) {
    internal fun resolvedServiceName(): String {
        if (!keychainService.isNullOrBlank()) return keychainService
        val bundleId = NSBundle.mainBundle.bundleIdentifier
        return if (!bundleId.isNullOrBlank()) {
            "io.github.encrypteddatastore.$bundleId"
        } else {
            "io.github.encrypteddatastore.default"
        }
    }
}

internal actual fun resolveEncryptedStoreFile(
    context: PlatformStorageContext,
    config: SecurityConfig,
): Pair<FileSystem, Path> {
    val baseDir = context.directoryPath ?: resolveDefaultAppSupportDir()
    val storeDir = "$baseDir/encrypted_datastore".toPath()
    FileSystem.SYSTEM.createDirectories(storeDir)
    chmod(storeDir.toString(), 0x1C0u) // 0700
    excludeFromBackup(storeDir.toString())
    val storeFile = storeDir / "${config.storeName}.edst"
    return FileSystem.SYSTEM to storeFile
}

private fun resolveDefaultAppSupportDir(): String {
    val urls = NSFileManager.defaultManager.URLsForDirectory(
        directory = NSApplicationSupportDirectory,
        inDomains = NSUserDomainMask,
    )
    val url = urls.firstOrNull() as? NSURL
    return url?.path ?: "/tmp"
}

private fun excludeFromBackup(path: String) {
    val url = NSURL.fileURLWithPath(path)
    url.setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
}

internal actual fun enforceRestrictiveFilePermissions(
    fileSystem: FileSystem,
    path: Path,
) {
    if (fileSystem !== FileSystem.SYSTEM) return
    if (!fileSystem.exists(path)) return
    chmod(path.toString(), 0x180u) // 0600
}

internal actual fun defaultIoCoroutineScope(): CoroutineScope =
    CoroutineScope(SupervisorJob() + Dispatchers.IO)

internal actual fun createPlatformKeyManager(
    context: PlatformStorageContext,
    config: SecurityConfig,
): KeyManager = IosKeychainKeyManager(context, config)
