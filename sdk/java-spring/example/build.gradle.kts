plugins {
    java
    id("org.springframework.boot")
}

description = "Moon SSO Spring Boot example application"

tasks.withType<JavaCompile>().configureEach {
    options.release = 21
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}

dependencies {
    implementation(platform(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES))
    implementation(project(":moon-sso-spring-boot-starter"))
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
}

