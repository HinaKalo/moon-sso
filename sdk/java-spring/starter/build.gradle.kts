plugins {
    `java-library`
    `maven-publish`
}

description = "Spring Boot starter for Moon SSO (OAuth 2.x / OpenID Connect)"

val springBootVersion = "4.2.0"

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release = 21
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-parameters", "-Xlint:all,-processing,-serial,-this-escape"))
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        charSet = "UTF-8"
        addBooleanOption("Xdoclint:none", true)
        addStringOption("quiet")
    }
}

dependencies {
    api(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
    annotationProcessor(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))

    api("org.springframework.boot:spring-boot-starter-webmvc")
    api("org.springframework.boot:spring-boot-starter-security-oauth2-client")
    api("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    api("org.springframework.boot:spring-boot-starter-restclient")

    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    annotationProcessor("org.springframework.boot:spring-boot-autoconfigure-processor")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.processResources {
    val props = mapOf("version" to project.version.toString())
    inputs.properties(props)
    filesMatching("META-INF/moon-sso-sdk.properties") {
        expand(props)
    }
}

val testbedUrl = providers.gradleProperty("moonSsoTestbed")
    .orElse(providers.environmentVariable("MOON_SSO_TESTBED"))
    .orElse("http://127.0.0.1:18601")

tasks.test {
    description = "Unit tests (no network)."
    useJUnitPlatform {
        excludeTags("testbed")
    }
}

val integrationTest by tasks.registering(Test::class) {
    description = "Integration tests against the Moon SSO testbed (MOON_SSO_TESTBED, default http://127.0.0.1:18601)."
    group = "verification"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    useJUnitPlatform {
        includeTags("testbed")
    }
    systemProperty("moon-sso.testbed", testbedUrl.get())
    shouldRunAfter(tasks.test)
    outputs.upToDateWhen { false }
}

tasks.withType<Test>().configureEach {
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

tasks.named("check") {
    dependsOn(integrationTest)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "moon-sso-spring-boot-starter"
            from(components["java"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }
            pom {
                name = "Moon SSO Spring Boot Starter"
                description = project.description
                url = "https://sso.moonl.cloud/docs"
                licenses {
                    license {
                        name = "Proprietary"
                        url = "https://sso.moonl.cloud/docs"
                    }
                }
                developers {
                    developer {
                        id = "moonl"
                        name = "Moon SSO"
                        url = "https://sso.moonl.cloud"
                    }
                }
                scm {
                    url = "https://sso.moonl.cloud/docs"
                }
            }
        }
    }
    repositories {
        maven {
            name = "buildRepo"
            url = uri(rootProject.layout.buildDirectory.dir("repo"))
        }
    }
}
