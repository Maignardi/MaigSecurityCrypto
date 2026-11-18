import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.kmp.library)
    `maven-publish`
}

val resolvedGroup = providers.gradleProperty("group").orNull
    ?.takeIf { it.isNotBlank() && it != "unspecified" }
    ?: System.getenv("GROUP")?.takeIf { it.isNotBlank() }
    ?: "io.github.maignardi"

val resolvedVersion = providers.gradleProperty("version").orNull
    ?.takeIf { it.isNotBlank() && it != "unspecified" }
    ?: System.getenv("VERSION")?.takeIf { it.isNotBlank() }
    ?: "0.2.1"

group = resolvedGroup
version = resolvedVersion

kotlin {
    explicitApi()

    targets.configureEach {
        compilations.configureEach {
            compileTaskProvider.configure {
                compilerOptions {
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                }
            }
        }
    }

    android {
        namespace = "io.github.encrypteddatastore"
        compileSdk = 35
        minSdk = 23

        withHostTestBuilder {
        }

        withDeviceTest {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }

        lint {
            abortOnError = true
            error += "NewApi"
        }

        optimization {
            consumerKeepRules.apply {
                publish = true
                file("consumer-rules.pro")
            }
        }

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(libs.androidx.datastore.core.okio)
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
            api(libs.okio)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.okio.fakefilesystem)
        }

        androidMain.dependencies {
            implementation(libs.tink.android)
            implementation(libs.kotlinx.coroutines.android)
        }

        getByName("androidHostTest").dependencies {
            implementation(libs.junit)
            implementation(libs.robolectric)
            implementation(libs.asm)
            implementation(libs.asm.commons)
            implementation(libs.asm.tree)
            implementation(libs.androidx.test.core)
        }

        getByName("androidDeviceTest").dependencies {
            implementation(libs.androidx.test.runner)
            implementation(libs.androidx.test.junit)
            implementation(libs.androidx.test.core)
            implementation(libs.kotlinx.coroutines.test)
        }

        jvmMain.dependencies {
            implementation(libs.tink.jvm)
        }

        jvmTest.dependencies {
            implementation(libs.junit)
        }

        iosMain.dependencies {
            implementation(libs.cryptography.core)
            implementation(libs.cryptography.provider.apple)
        }
    }
}

val verifyAndroidMinSdk23Compatibility = tasks.register("verifyAndroidMinSdk23Compatibility") {
    group = "verification"
    description = "Scans compiled androidMain bytecode for API 26+ java.nio.file / java.time references."
    val compileJarTask = tasks.named("bundleAndroidMainClassesToCompileJar")
    dependsOn(compileJarTask)
    inputs.files(compileJarTask)
    doLast {
        val jarFile = compileJarTask.get().outputs.files.singleFile
        val forbiddenTokens = listOf("java/nio/file/", "java/time/")
        val violations = mutableListOf<String>()
        ZipFile(jarFile).use { zip ->
            zip.entries().asSequence()
                .filter { !it.isDirectory && it.name.endsWith(".class") }
                .forEach { entry ->
                    val bytes = zip.getInputStream(entry).readBytes()
                    val text = bytes.toString(Charsets.ISO_8859_1)
                    forbiddenTokens.forEach { token ->
                        if (text.contains(token)) {
                            violations += "${entry.name} references forbidden API 26+ package '$token'"
                        }
                    }
                }
        }
        if (violations.isNotEmpty()) {
            throw GradleException("minSdk=23 bytecode check failed:\n" + violations.joinToString("\n"))
        }
    }
}

tasks.named("check").configure {
    dependsOn(verifyAndroidMinSdk23Compatibility)
}

publishing {
    repositories {
        maven {
            name = "GitHubPackages"
            val repo = System.getenv("GITHUB_REPOSITORY") ?: "Maignardi/encrypted-datastore"
            url = uri("https://maven.pkg.github.com/$repo")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                    ?: providers.gradleProperty("gpr.user").orNull
                password = System.getenv("GITHUB_TOKEN")
                    ?: providers.gradleProperty("gpr.key").orNull
            }
        }
    }

    publications.withType<MavenPublication>().configureEach {
        pom {
            name.set("EncryptedDataStore")
            description.set(
                "Security-first Kotlin Multiplatform encrypted DataStore & EncryptedPreferences " +
                    "built on Jetpack DataStore, Google Tink, AndroidKeyStore/StrongBox, and iOS Keychain."
            )
            licenses {
                license {
                    name.set("Apache-2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
        }
    }
}
