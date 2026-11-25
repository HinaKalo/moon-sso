import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "cloud.moonl.sso.sample"
    compileSdk = 36

    defaultConfig {
        // Matches the redirect URI com.example.test:/oauth2redirect of the testbed client test-native.
        applicationId = "com.example.test"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        manifestPlaceholders["moonSsoRedirectScheme"] = "com.example.test"
        // With `adb reverse tcp:18601 tcp:18601` the device reaches the local testbed on 127.0.0.1.
        buildConfigField("String", "MOON_SSO_ISSUER", "\"${providers.gradleProperty("moonSsoIssuer").getOrElse("http://127.0.0.1:18601")}\"")
        buildConfigField("String", "MOON_SSO_CLIENT_ID", "\"${providers.gradleProperty("moonSsoClientId").getOrElse("test-native")}\"")
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

dependencies {
    implementation(project(":android"))
    implementation(libs.androidx.activity)
    implementation(libs.androidx.lifecycle.runtime.ktx)
}
