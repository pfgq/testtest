plugins {
    id("com.android.application")
}

android {
    namespace = "com.system.uitest"
    compileSdk = 37
    ndkVersion = "24.0.8215888"

    defaultConfig {
        applicationId = "com.system.testsu"
        minSdk = 30
        targetSdk = 37
        versionCode = 46
        versionName = "1.29"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        create("keystore") {
            storeFile = file("keystore.jks")
            storePassword = "dirtyfrag"
            keyAlias = "dirtyfrag"
            keyPassword = "dirtyfrag"
        }
    }

    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("keystore")
        }
        release {
            signingConfig = signingConfigs.getByName("keystore")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

// AGP 9 removed the old applicationVariants API; this is the replacement.
androidComponents {
    onVariants { variant ->
        variant.outputs.forEach { output ->
            output.outputFileName.set("dirtyfrag.apk")
        }
    }
}
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        checkReleaseBuilds = false
    }

    buildFeatures {
        viewBinding = true
        // The toolbar version pill reads BuildConfig.VERSION_NAME, so the pill
        // can never fall behind versionName again.
        buildConfig = true
    }

    // Native payloads are built out-of-band with NDK r24 (aarch64 host) and
    // dropped into src/main/jniLibs/arm64-v8a; see build notes.
    // externalNativeBuild {
    //     cmake {
    //         path("src/main/jni/CMakeLists.txt")
    //     }
    // }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
}
