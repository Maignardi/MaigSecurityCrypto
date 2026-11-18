# Keep kotlinx.serialization internal metadata & preference models under R8/ProGuard
-keep,includedescriptorclasses class io.github.encrypteddatastore.**$$serializer { *; }
-keepclassmembers class io.github.encrypteddatastore.** {
    *** Companion;
}
-keepclassmembers class io.github.encrypteddatastore.PreferenceValueType {
    <fields>;
}
