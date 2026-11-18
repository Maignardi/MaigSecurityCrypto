package io.github.maigsecuritycrypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi

/**
 * Isolated `Build.VERSION.SDK_INT`-guarded API helpers so `AndroidKeyStoreAead` passes
 * ART verification on API 23 and Animal Sniffer API 23 signature verification.
 */
@RequiresApi(24)
internal object Api24KeyStoreImpl {
    fun setInvalidatedByBiometricEnrollment(
        builder: KeyGenParameterSpec.Builder,
        invalidate: Boolean,
    ) {
        builder.setInvalidatedByBiometricEnrollment(invalidate)
    }
}

@RequiresApi(28)
internal object Api28KeyStoreImpl {
    fun setIsStrongBoxBacked(
        builder: KeyGenParameterSpec.Builder,
        strongBox: Boolean,
    ) {
        builder.setIsStrongBoxBacked(strongBox)
    }

    fun isStrongBoxUnavailableException(t: Throwable): Boolean =
        t is StrongBoxUnavailableException
}

@RequiresApi(30)
internal object Api30KeyStoreImpl {
    fun setUserAuthenticationParameters(
        builder: KeyGenParameterSpec.Builder,
        timeoutSeconds: Int,
        allowDeviceCredential: Boolean,
    ) {
        val authTypes = if (allowDeviceCredential) {
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        } else {
            KeyProperties.AUTH_BIOMETRIC_STRONG
        }
        builder.setUserAuthenticationParameters(timeoutSeconds, authTypes)
    }
}

@RequiresApi(31)
internal object Api31KeyStoreImpl {
    fun resolveSecurityLevel(info: KeyInfo): MaigSecurityLevel = when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> MaigSecurityLevel.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> MaigSecurityLevel.HARDWARE_TEE
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> MaigSecurityLevel.SOFTWARE_FALLBACK
        else -> MaigSecurityLevel.UNKNOWN
    }
}
