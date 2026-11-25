import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    `maven-publish`
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

dependencies {
    api(project(":core"))
    implementation(libs.jna)
    implementation(libs.jna.platform)

    testImplementation(kotlin("test"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    systemProperty("moonsso.testbed", providers.environmentVariable("MOON_SSO_TESTBED").getOrElse("http://127.0.0.1:18601"))
    // Used to start a second JVM in the cross-process lock test.
    systemProperty("moonsso.testClasspath", sourceSets.test.get().runtimeClasspath.asPath)
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "moon-sso-desktop"
            from(components["java"])
        }
    }
}
