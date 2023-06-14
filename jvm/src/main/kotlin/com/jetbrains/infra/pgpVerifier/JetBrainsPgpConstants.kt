package com.jetbrains.infra.pgpVerifier

@Suppress("SpellCheckingInspection")
object JetBrainsPgpConstants {

    // download@jetbrains.com public key. expiration date is missing by design.
    // we assume that the primary key is never compromised (you need to trust something)
    // but subkeys (actually used to sign content) may be freely added/removed or revoked
    // NOTE: this is ArmoredOutputStream(ByteArrayOutputStream()).use { it.write(trustedMasterKey.publicKeyPacket.encoded) }
    val JETBRAINS_DOWNLOADS_PGP_MASTER_PUBLIC_KEY = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----

        mQGNBGBP58sBDADYRZmxLOkqrz0QZ/yESRpv7IeHGLqDE1a8QfFtFb14MJCLSAAS
        3nMD6Szi9mEjEqYdJURRcMjbUBhePgbhzGa3FYkjAB8lj6IKbu+ogCwVm1S8+caZ
        C6HNP1CIefa1wQgi/6FNWEBKbKefUr/DoG1fBAWUvTPC2BjiYOHDaU1xFWwhF3Np
        p0gEoK2KNgGgy/aSCi9Rb1M1ynPF7CcY8vKpAo6YfJpoNnput3t5FoF0uPnIac0F
        gikw6Iz8knUoYeqW2MTKNBxgQrtS+Ji1J0EgzT2Nq1SBMPfmq4/h1+XOQweWY/NR
        GNQTzcR3v+FkLkqCIaywcWUMXkhFXB8U3TdPa4bCEbFlP/AUkEw0X/obxm0isshU
        w7MRMPoBXR3FkEApkxB+bFptY3ZbBYhu5PCf4FWBE8+FkYEJ31IS+nABC2u9Jcav
        o5TqVd0y4e8VZ2qz18ez3j2G+nVthHz2OZ3AdEmq60K6iD57RY0H8zQK7xeEe3Ye
        VoRmpZdS8Eyk2aEAEQEAAQ==
        =MhMZ
        -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()

    const val JETBRAINS_DOWNLOADS_PGP_SUB_KEYS_URL = "https://download.jetbrains.com/KEYS"
}
