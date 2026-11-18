import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.kmp.library)
    `maven-publish`
}

val resolvedGroup = providers.gradleProperty("group").orNull
    ?.takeIf { it.isNotBlank() && it != "unspecified" }
    ?: System.getenv("GROUP")?.takeIf { it.isNotBlank() }
    ?: "io.github.encrypteddatastore"

val resolvedVersion = providers.gradleProperty("version").orNull
    ?.takeIf { it.isNotBlank() && it != "unspecified" }
    ?: System.getenv("VERSION")?.takeIf { it.isNotBlank() }
    ?: "0.1.0"

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
    iosX64()

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
            implementation(libs.tink.jvm)
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
