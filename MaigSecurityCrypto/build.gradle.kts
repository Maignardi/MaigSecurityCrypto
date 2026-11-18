import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.File
import java.io.InputStream
import java.lang.reflect.Proxy
import java.net.URLClassLoader
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

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
    ?: "0.3.2"

val resolvedArtifactBase = providers.gradleProperty("artifactId").orNull
    ?.takeIf { it.isNotBlank() && it != "unspecified" }

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
        namespace = "io.github.maigsecuritycrypto"
        compileSdk = 35
        minSdk = 23

        withHostTestBuilder {
        }

        withDeviceTest {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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

val animalSnifferSignature: Configuration = configurations.create("animalSnifferSignature")
val animalSnifferTool: Configuration = configurations.create("animalSnifferTool")

dependencies {
    animalSnifferSignature("com.toasttab.android:gummy-bears-api-23:${libs.versions.gummy.bears.get()}@signature")
    animalSnifferTool(libs.animal.sniffer)
}

val verifyAndroidMinSdk23Compatibility = tasks.register("verifyAndroidMinSdk23Compatibility") {
    group = "verification"
    description = "Checks all compiled androidMain classes against Android API 23 signatures (gummy-bears-api-23)."
    val compileJarTask = tasks.named("bundleAndroidMainClassesToCompileJar")
    dependsOn(compileJarTask)
    inputs.files(compileJarTask, animalSnifferSignature)
    doLast {
        val jarFile = compileJarTask.get().outputs.files.singleFile
        val signatureFile = animalSnifferSignature.singleFile
        val toolUrls = animalSnifferTool.files.map { it.toURI().toURL() }.toTypedArray()

        val loader = URLClassLoader(toolUrls, ClassLoader.getPlatformClassLoader())
        val checkerClass = loader.loadClass("org.codehaus.mojo.animal_sniffer.SignatureChecker")
        val loggerClass = loader.loadClass("org.codehaus.mojo.animal_sniffer.logging.Logger")
        val loggerProxy = Proxy.newProxyInstance(
            loader,
            arrayOf(loggerClass),
        ) { _, method, args ->
            if (method.name == "error" && args != null && args.isNotEmpty()) {
                logger.error(args[0]?.toString())
            }
            null
        }

        val ctor = checkerClass.getConstructor(
            InputStream::class.java,
            Set::class.java,
            loggerClass,
        )
        val ignoredPackages = setOf(
            "androidx.*",
            "com.google.*",
            "kotlinx.*",
            "kotlin.*",
            "okio.*",
            "io.github.maigsecuritycrypto.*",
            "org.jetbrains.*",
        )
        val checker = signatureFile.inputStream().use { sigStream ->
            ctor.newInstance(sigStream, ignoredPackages, loggerProxy)
        }
        checkerClass.getMethod("setCheckJars", Boolean::class.javaPrimitiveType).invoke(checker, true)
        checkerClass.getMethod("setSourcePath", List::class.java).invoke(checker, emptyList<File>())
        // Check every class EXCEPT the intentionally SDK_INT-gated Api24/28/30/31 compat helpers
        val filteredJar = File.createTempFile("edst-minsdk-check", ".jar")
        try {
            ZipFile(jarFile).use { inputZip ->
                ZipOutputStream(filteredJar.outputStream()).use { outZip ->
                    inputZip.entries().asSequence().forEach { entry ->
                        val isGatedCompat = entry.name.endsWith("KeyStoreImpl.class")
                        if (!isGatedCompat) {
                            outZip.putNextEntry(ZipEntry(entry.name))
                            inputZip.getInputStream(entry).copyTo(outZip)
                            outZip.closeEntry()
                        }
                    }
                }
            }
            checkerClass.getMethod("process", Array<File>::class.java).invoke(checker, arrayOf(filteredJar))
        } finally {
            filteredJar.delete()
        }
        val isSigBroken = checkerClass.getMethod("isSignatureBroken").invoke(checker) as Boolean
        if (isSigBroken) {
            throw GradleException("Animal Sniffer detected Android API > 23 references in androidMain bytecode.")
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
            val repo = System.getenv("GITHUB_REPOSITORY") ?: "Maignardi/MaigSecurityCrypto"
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
        if (resolvedArtifactBase != null) {
            val targetSuffix = if (name == "kotlinMultiplatform") "" else "-${name.lowercase()}"
            artifactId = "$resolvedArtifactBase$targetSuffix"
        }
        pom {
            name.set("MaigSecurityCrypto")
            description.set(
                "MaigSecurityCrypto: security-first Kotlin Multiplatform encrypted DataStore & Preferences " +
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
