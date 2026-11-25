plugins {
    id("org.springframework.boot") version "4.2.0" apply false
}

allprojects {
    group = "cloud.moonl.sso"
    version = "0.1.0"
    repositories {
        mavenCentral()
    }
}

tasks.register("publishToBuildRepo") {
    group = "publishing"
    description = "Publishes the starter to build/repo (static Maven repository served at https://sso.moonl.cloud/sdk/maven)."
    dependsOn(":moon-sso-spring-boot-starter:publishMavenPublicationToBuildRepoRepository")
}
