plugins {
    id("com.android.kotlin.multiplatform.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
}

kotlin {
    android {
        namespace = "example.auth"
        compileSdk = 35
        minSdk = 24
    }
    iosArm64()
    iosSimulatorArm64()
    iosX64()

    sourceSets {
        commonMain.dependencies {
            implementation("io.ktor:ktor-client-core:3.1.1")
            implementation("io.ktor:ktor-client-content-negotiation:3.1.1")
            implementation("io.ktor:ktor-serialization-kotlinx-json:3.1.1")
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1")
        }
    }

}
