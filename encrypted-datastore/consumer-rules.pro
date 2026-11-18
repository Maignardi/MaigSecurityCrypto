# Keep kotlinx.serialization internal metadata & preference models under R8/ProGuard
-keep,includedescriptorclasses class io.github.maigsecuritycrypto.**$$serializer { *; }
-keepclassmembers class io.github.maigsecuritycrypto.** {
    *** Companion;
}
-keepclassmembers class io.github.maigsecuritycrypto.PreferenceValueType {
    <fields>;
}
