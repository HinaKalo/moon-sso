plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}

val sdkVersion: String = providers.gradleProperty("moonSsoVersion").get()
val buildRepoDir = layout.buildDirectory.dir("repo")

allprojects {
    group = "cloud.moonl.sso"
    version = sdkVersion
}

// Shared Maven publication settings for the library modules (:core, :android, :desktop).
subprojects {
    plugins.withId("maven-publish") {
        extensions.configure<PublishingExtension> {
            repositories {
                maven {
                    name = "buildRepo"
                    url = uri(buildRepoDir)
                }
            }
            publications.withType<MavenPublication>().configureEach {
                pom {
                    name.set("Moon SSO Kotlin SDK (${project.name})")
                    description.set("Kotlin SDK for Moon SSO (OAuth 2.x / OpenID Connect) — Android and JVM desktop.")
                    url.set("https://sso.moonl.cloud/docs")
                    licenses {
                        license {
                            name.set("Proprietary")
                            url.set("https://sso.moonl.cloud/docs")
                        }
                    }
                }
            }
        }
    }
}

tasks.register("publishToBuildRepo") {
    group = "publishing"
    description = "Publishes all SDK artifacts to build/repo (static Maven layout served at https://sso.moonl.cloud/sdk/maven)."
    dependsOn(
        ":core:publishAllPublicationsToBuildRepoRepository",
        ":android:publishAllPublicationsToBuildRepoRepository",
        ":desktop:publishAllPublicationsToBuildRepoRepository",
    )
}
