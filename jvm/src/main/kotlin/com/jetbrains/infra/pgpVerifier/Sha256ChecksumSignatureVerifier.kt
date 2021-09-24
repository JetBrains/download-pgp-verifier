package com.jetbrains.infra.pgpVerifier

import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest


object Sha256ChecksumSignatureVerifier {
    private val sha256WithFileNameRegex = Regex("([0-9a-f]{64})[\t ]+\\*?([a-zA-Z0-9_\\-.*]+)\\s*")

    private fun getHashFromChecksumFile(
        detachedSignatureFile: Path,
        checksumFile: Path,
        expectedFileName: String,
        untrustedPublicKeyRing: InputStream,
        trustedMasterKey: InputStream,
        logger: PgpSignaturesVerifierLogger,
    ): String {
        Files.newInputStream(detachedSignatureFile).use { signatureStream ->
            PgpSignaturesVerifier.verifySignature(
                file = checksumFile,
                detachedSignatureInputStream = signatureStream,
                untrustedPublicKeyBundleInputStream = untrustedPublicKeyRing,
                trustedMasterKeyInputStream = trustedMasterKey,
                logger = logger,
            )
        }

        val text = Files.readString(checksumFile)
        val match = sha256WithFileNameRegex.matchEntire(text) ?: error("Checksum file does not match regex '$sha256WithFileNameRegex': ~~~$text~~~")
        val actualFileName = match.groupValues[2]

        if (actualFileName != expectedFileName) {
            error("Expected file name '$expectedFileName', but got '$actualFileName' in checksum file: ~~~$text~~~")
        }

        return match.groupValues[1]
    }

    fun verifyChecksumAndSignature(
        file: Path,
        detachedSignatureFile: Path,
        checksumFile: Path,
        expectedFileName: String,
        untrustedPublicKeyRing: InputStream,
        trustedMasterKey: InputStream,
        logger: PgpSignaturesVerifierLogger,
    ) {
        val expectedHash = getHashFromChecksumFile(
            detachedSignatureFile = detachedSignatureFile,
            checksumFile = checksumFile,
            expectedFileName = expectedFileName,
            untrustedPublicKeyRing = untrustedPublicKeyRing,
            trustedMasterKey = trustedMasterKey,
            logger = logger,
        )

        val actualByteHash = getFileDigest(file, MessageDigest.getInstance("SHA-256"))
        val actualHash = actualByteHash.toHexString()

        if (expectedHash != actualHash) {
            error(
                "Failed to verify SHA-256 checksum for $file\n\n" +
                        "The actual value is $actualHash,\n" +
                        "but $expectedHash was expected"
            )
        }
    }

    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

    private fun getFileDigest(file: Path, digest: MessageDigest): ByteArray {
        val buf = ByteArray(65536)

        digest.reset()
        Files.newInputStream(file).use {
            while (true) {
                val count = it.read(buf)
                if (count <= 0) break

                digest.update(buf, 0, count)
            }
        }
        return digest.digest()
    }
}