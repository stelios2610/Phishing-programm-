plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.phishguard.scanner"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.phishguard.scanner"
        minSdk = 26
        targetSdk = 36
        versionCode = 2
        versionName = "1.0.1"
    }

    val uploadStore = System.getenv("PHISHGUARD_STORE_FILE")
    if (!uploadStore.isNullOrBlank()) {
        signingConfigs {
            create("upload") {
                storeFile = file(uploadStore)
                storePassword = System.getenv("PHISHGUARD_STORE_PASSWORD") ?: ""
                keyAlias = System.getenv("PHISHGUARD_KEY_ALIAS") ?: "phishguard"
                keyPassword = System.getenv("PHISHGUARD_KEY_PASSWORD") ?: ""
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (!uploadStore.isNullOrBlank()) {
                signingConfig = signingConfigs.getByName("upload")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.webkit:webkit:1.11.0")
}
