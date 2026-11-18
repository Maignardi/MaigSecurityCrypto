package io.github.encrypteddatastore.sample

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import io.github.encrypteddatastore.EncryptedPreferences
import io.github.encrypteddatastore.PreferenceKeys
import io.github.encrypteddatastore.SecurityDiagnostics
import kotlinx.coroutines.launch

object VaultKeys {
    val apiToken = PreferenceKeys.string("api_token")
}

@Composable
fun EncryptedVaultScreen(
    prefs: EncryptedPreferences,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val storedToken by prefs.observe(VaultKeys.apiToken).collectAsState(initial = null)
    var tokenInput by remember { mutableStateOf("") }
    var diagnostics by remember { mutableStateOf<SecurityDiagnostics?>(null) }
    var errorText by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(storedToken) {
        runCatching { prefs.diagnostics() }
            .onSuccess { diagnostics = it }
            .onFailure { errorText = it.message }
    }

    Surface(modifier = modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = "EncryptedDataStore Vault",
                style = MaterialTheme.typography.headlineSmall,
            )

            OutlinedTextField(
                value = tokenInput,
                onValueChange = { tokenInput = it },
                label = { Text("Secret Token") },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("token_input"),
                singleLine = true,
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        scope.launch {
                            errorText = null
                            runCatching {
                                prefs.edit { it[VaultKeys.apiToken] = tokenInput }
                                diagnostics = prefs.diagnostics()
                            }.onFailure { errorText = it.message }
                        }
                    },
                    modifier = Modifier.testTag("save_button"),
                ) {
                    Text("Save Encrypted")
                }

                OutlinedButton(
                    onClick = {
                        scope.launch {
                            errorText = null
                            runCatching {
                                prefs.rotateKeys()
                                diagnostics = prefs.diagnostics()
                            }.onFailure { errorText = it.message }
                        }
                    },
                    modifier = Modifier.testTag("rotate_button"),
                ) {
                    Text("Rotate Key")
                }

                OutlinedButton(
                    onClick = {
                        scope.launch {
                            errorText = null
                            runCatching {
                                prefs.clearAndReset()
                                tokenInput = ""
                                diagnostics = prefs.diagnostics()
                            }.onFailure { errorText = it.message }
                        }
                    },
                    modifier = Modifier.testTag("wipe_button"),
                ) {
                    Text("Secure Wipe")
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = "Decrypted Token: ${storedToken ?: "<empty>"}",
                        modifier = Modifier.testTag("decrypted_token"),
                    )
                    diagnostics?.let { diag ->
                        Text(
                            text = "Security Level: ${diag.securityLevel}",
                            modifier = Modifier.testTag("security_level"),
                        )
                        Text(
                            text = "Key Epoch: ${diag.currentKeyEpoch}",
                            modifier = Modifier.testTag("key_epoch"),
                        )
                        Text(
                            text = "Algorithm: ${diag.algorithm}",
                            modifier = Modifier.testTag("algorithm"),
                        )
                    }
                    errorText?.let { err ->
                        Text(
                            text = "Error: $err",
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.testTag("error_text"),
                        )
                    }
                }
            }
        }
    }
}
