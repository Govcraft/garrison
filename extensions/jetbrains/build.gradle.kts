plugins {
    java
    id("org.jetbrains.intellij.platform") version "2.18.1"
}

group = "com.govcraft.garrison"
version = "0.1.0"

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    implementation("com.google.code.gson:gson:2.13.1")
    intellijPlatform { intellijIdea("2025.3.6") }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.withType<JavaCompile>().configureEach { options.release = 21 }

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "253"
            untilBuild = provider { null }
        }
    }
}
