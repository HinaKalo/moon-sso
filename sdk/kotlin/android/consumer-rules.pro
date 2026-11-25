# Moon SSO Android SDK — rules applied to apps that enable R8/ProGuard.

# nimbus-jose-jwt references optional providers that are not on the classpath.
-dontwarn com.google.crypto.tink.**
-dontwarn org.bouncycastle.**
-dontwarn net.jcip.annotations.**
-dontwarn com.google.errorprone.annotations.**

# Session JSON models (kotlinx.serialization generated serializers).
-keepclassmembers class cloud.moonl.sso.** {
    *** Companion;
}
-keepclasseswithmembers class cloud.moonl.sso.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class cloud.moonl.sso.**$$serializer { *; }
