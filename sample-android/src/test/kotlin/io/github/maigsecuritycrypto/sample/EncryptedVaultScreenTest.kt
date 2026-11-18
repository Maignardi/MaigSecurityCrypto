package io.github.maigsecuritycrypto.sample

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import io.github.maigsecuritycrypto.MaigCipherAlgorithm
import io.github.maigsecuritycrypto.MaigKeystoreRecoveryPolicy
import io.github.maigsecuritycrypto.MaigSecurityConfig
import io.github.maigsecuritycrypto.MaigSecurityCrypto
import io.github.maigsecuritycrypto.MaigStorageContext
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EncryptedVaultScreenTest {

    @get:Rule
    val composeRule = createComposeRule()

    private val prefs = MaigSecurityCrypto.createPreferences(
        context = MaigStorageContext(ApplicationProvider.getApplicationContext()),
        config = MaigSecurityConfig(
            storeName = "ui_test_vault",
            algorithm = MaigCipherAlgorithm.AES256_GCM,
            recoveryPolicy = MaigKeystoreRecoveryPolicy.EXPLICIT_SOFTWARE_FALLBACK,
        ),
    )

    @After
    fun tearDown() = runBlocking {
        prefs.close()
    }

    @Test
    fun saveRotateAndWipeFlowUpdatesUiReactively() {
        composeRule.setContent {
            MaterialTheme {
                EncryptedVaultScreen(prefs = prefs)
            }
        }

        composeRule.onNodeWithTag("decrypted_token")
            .assertTextEquals("Decrypted Token: <empty>")

        // Save encrypted secret from UI
        composeRule.onNodeWithTag("token_input").performTextInput("jwt_ui_secret_123")
        composeRule.onNodeWithTag("save_button").performClick()

        composeRule.waitUntil(timeoutMillis = 5_000) {
            runCatching {
                composeRule.onNodeWithTag("decrypted_token")
                    .assertTextEquals("Decrypted Token: jwt_ui_secret_123")
                true
            }.getOrDefault(false)
        }
        composeRule.onNodeWithTag("key_epoch").assertTextEquals("Key Epoch: 1")

        // Rotate key from UI -> epoch becomes 2 while data stays decrypted
        composeRule.onNodeWithTag("rotate_button").performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            runCatching {
                composeRule.onNodeWithTag("key_epoch").assertTextEquals("Key Epoch: 2")
                true
            }.getOrDefault(false)
        }
        composeRule.onNodeWithTag("decrypted_token")
            .assertTextEquals("Decrypted Token: jwt_ui_secret_123")

        // Secure Wipe -> clears token and resets state
        composeRule.onNodeWithTag("wipe_button").performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            runCatching {
                composeRule.onNodeWithTag("decrypted_token")
                    .assertTextEquals("Decrypted Token: <empty>")
                true
            }.getOrDefault(false)
        }
    }
}
