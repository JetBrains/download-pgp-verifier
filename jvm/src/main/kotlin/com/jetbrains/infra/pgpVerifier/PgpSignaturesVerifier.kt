package com.jetbrains.infra.pgpVerifier

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.jetbrains.annotations.TestOnly
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant


class PgpSignaturesVerifier(private val logger: PgpSignaturesVerifierLogger) {
    private val bouncyCastleProvider = BouncyCastleProvider()

    private var currentTimeProvider = { Instant.now() }

    fun verifySignature(
        file: Path,
        detachedSignatureInputStream: InputStream,
        untrustedPublicKeyBundleInputStream: InputStream,
        trustedMasterKeyInputStream: InputStream,
    ) {
        val signatures = getSignaturesFromFile(detachedSignatureInputStream)
        val untrustedPublicKeyRingCollection = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(untrustedPublicKeyBundleInputStream),
            JcaKeyFingerprintCalculator()
        )
        val trustedMasterKey = getTrustedMasterKey(trustedMasterKeyInputStream)
        val currentInstant = currentTimeProvider()

        var verified = false

        val buf = ByteArray(16384)
        for (signature in signatures) {
            val signatureCheckError = checkSignatureFormat(signature)
            if (signatureCheckError != null) {
                logger.info("Signature skipped: $signatureCheckError")
                continue
            }

            val key = untrustedPublicKeyRingCollection.getPublicKey(signature.keyID) ?: continue
            val keyCheckError = checkPublicKeyFormat(key)
            if (keyCheckError != null) {
                logger.info("Key skipped: $keyCheckError")
                continue
            }
            if (!isSubKeyForSigning(key, trustedMasterKey, currentInstant, logger)) {
                continue
            }
            if (isRevoked(key, signature)) {
                logger.info("Key (ID:${key.keyID.toKeyIdString()}) was revoked before signature timestamp")
                continue
            }

            signature.init(JcaPGPContentVerifierBuilderProvider().setProvider(bouncyCastleProvider), key)
            Files.newInputStream(file).use { stream ->
                while (true) {
                    val bytes = stream.read(buf)
                    if (bytes < 0) break
                    signature.update(buf, 0, bytes)
                }
            }
            if (!signature.verify()) {
                // No bad signatures are tolerated
                error("Signature verification failed for $file")
            }

            // At this point we verified that
            //  - our content was indeed signed by untrusted key `key`
            // `- key` and `signature` are good enough
            //  - key is signed by our trusted primary key
            //  - key was not revoked before making `signature`
            verified = true
        }

        if (!verified) {
            error("No keys matched signature for $file")
        }
    }

    private fun getTrustedMasterKey(trustedMasterKeyInputStream: InputStream): PGPPublicKey {
        val publicKeyPacket = BCPGInputStream(ArmoredInputStream(trustedMasterKeyInputStream)).use {
            val packet = it.readPacket() as PublicKeyPacket

            val rest = it.readAllBytes()
            if (rest.isNotEmpty()) {
                error("Some leftovers in the stream after reading PublicKeyPacket")
            }

            packet
        }

        val trustedMasterKey = PGPPublicKey(publicKeyPacket, JcaKeyFingerprintCalculator())
        require(trustedMasterKey.isMasterKey) { "Key ${trustedMasterKey.keyID.toKeyIdString()} must be a master key" }
        assertPublicKeyFormat(trustedMasterKey)

        return trustedMasterKey
    }

    private fun getSignaturesFromFile(detachedSignatureInputStream: InputStream): PGPSignatureList {
        val detachedSignatureDecoder = PGPUtil.getDecoderStream(detachedSignatureInputStream)

        var pgpFact = JcaPGPObjectFactory(detachedSignatureDecoder)
        val p3: PGPSignatureList
        val o = pgpFact.nextObject() ?: error("PGP signature stream is empty")
        if (o is PGPCompressedData) {
            val c1: PGPCompressedData = o
            pgpFact = JcaPGPObjectFactory(c1.dataStream)
            p3 = pgpFact.nextObject() as PGPSignatureList
        } else {
            p3 = o as PGPSignatureList
        }
        return p3
    }

    private fun isRevoked(subKey: PGPPublicKey, signature: PGPSignature): Boolean {
        for (revocationSignature in subKey.signatures) {
            if (revocationSignature.signatureType == PGPSignature.SUBKEY_REVOCATION) {
                if (revocationSignature.creationTime <= signature.creationTime) {
                    return true
                }
            }
        }

        return false
    }

    private fun isSubKeyForSigning(subKey: PGPPublicKey, masterKey: PGPPublicKey, currentInstant: Instant, logger: PgpSignaturesVerifierLogger): Boolean {
        require(masterKey.isMasterKey) { "Key ${masterKey.keyID.toKeyIdString()} must be a master key" }
        require(!subKey.isMasterKey) { "Key ${subKey.keyID.toKeyIdString()} must be a sub key" }

        for (signature in subKey.keySignatures) {
            if (signature !is PGPSignature) continue
            if (signature.signatureType != PGPSignature.SUBKEY_BINDING) continue
            if (signature.keyID != masterKey.keyID) continue
            if (!isSignKey(signature)) continue

            val signatureCheckError = checkSignatureFormat(signature)
            if (signatureCheckError != null) {
                logger.info("Signature for key '${subKey.keyID.toKeyIdString()}' was skipped due to wrong format: $signatureCheckError")
                continue
            }

            val expirationCheckError = checkExpiration(signature, currentInstant)
            if (expirationCheckError != null) {
                logger.info("Signature for key '${subKey.keyID.toKeyIdString()}' was skipped due to expiration issue: $expirationCheckError")
                continue
            }

            signature.init(JcaPGPContentVerifierBuilderProvider().setProvider(bouncyCastleProvider), masterKey)
            if (signature.verifyCertification(masterKey, subKey)) {
                return true
            }
        }

        return false
    }

    private fun isSignKey(sig: PGPSignature): Boolean = (sig.hashedSubPackets.keyFlags and KeyFlags.SIGN_DATA) != 0

    private fun checkExpiration(signature: PGPSignature, currentInstant: Instant): String? {
        if (!signature.hashedSubPackets.hasSubpacket(SignatureSubpacketTags.KEY_EXPIRE_TIME)) {
            return "Expiration is missing in signature"
        }

        val keyLifetimeSeconds = signature.hashedSubPackets.keyExpirationTime
        when {
            keyLifetimeSeconds < 0L -> return "Invalid 'keyExpirationTime' in signature: $keyLifetimeSeconds"
            keyLifetimeSeconds == 0L -> return "Signature must have an expiration"
        }

        val keyLifetimeDuration = Duration.ofSeconds(keyLifetimeSeconds)
        if (keyLifetimeDuration > Duration.ofDays(6 * 365L)) {
            return "Signature expiration must not be more than 6 years"
        }

        val creationInstant = signature.creationTime.toInstant()
        if (currentInstant.isBefore(creationInstant)) {
            return "Signature creation time must be in the past"
        }
        if (Duration.between(creationInstant, currentInstant) > Duration.ofDays(30 * 365L)) {
            return "Signature created more than 30 years in the past, this is not supported"
        }

        val keyExpirationInstant = creationInstant + keyLifetimeDuration
        if (keyExpirationInstant < currentInstant) {
            return "Signature expired"
        }

        return null
    }

    private fun checkPublicKeyFormat(key: PGPPublicKey): String? {
        if (key.version != 4) {
            return "Only PGP Public Keys version 4 are supported. Key ID = " + java.lang.Long.toHexString(key.keyID)
        }

        if (key.bitStrength < 2048 || key.bitStrength > 100000) {
            return "Only PGP Public Keys bits >= 2048. Key ID = " + java.lang.Long.toHexString(key.keyID)
        }

        return null
    }

    private fun assertPublicKeyFormat(key: PGPPublicKey) {
        val errorString = checkPublicKeyFormat(key)
        if (errorString != null) {
            error(errorString)
        }
    }

    private fun checkSignatureFormat(sig: PGPSignature): String? {
        if (sig.hashAlgorithm != HashAlgorithmTags.SHA256 && sig.hashAlgorithm != HashAlgorithmTags.SHA384 && sig.hashAlgorithm != HashAlgorithmTags.SHA512) {
            return "Only hashAlgorithms SHA256/384/512 are supported. See https://tools.ietf.org/html/rfc4880#section-9.4"
        }

        if (sig.keyAlgorithm != PublicKeyAlgorithmTags.RSA_GENERAL) {
            return "Only keyAlgorithm = 1 (RSA (Encrypt or Sign)) is supported. See https://tools.ietf.org/html/rfc4880#section-9.1"
        }

        return null
    }

    private fun Long.toKeyIdString(): String = java.lang.Long.toHexString(this).uppercase()

    @TestOnly
    internal fun setCurrentTimeProvider(timeProvider: () -> Instant) {
        currentTimeProvider = timeProvider
    }
}