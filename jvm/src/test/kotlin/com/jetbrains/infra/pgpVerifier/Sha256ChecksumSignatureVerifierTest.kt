@file:Suppress("SpellCheckingInspection")

package com.jetbrains.infra.pgpVerifier

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayInputStream

class Sha256ChecksumSignatureVerifierTest {
    @Test
    fun wrongFileName() {
        val ex = assertThrows<IllegalStateException> {
            runTest(
                detachedSignatureFileName = "lorem-ipsum2.txt.sha256.asc",
                checksumFile = "lorem-ipsum2.txt.sha256",
            )
        }
        Assertions.assertTrue(ex.message!!.startsWith("Expected file name 'lorem-ipsum.txt', but got 'lorem-ipsum2.txt' in checksum file"), ex.message!!)
    }

    @Test
    fun wrongChecksum() {
        val ex = assertThrows<IllegalStateException> {
            runTest(detachedSignatureFileName = "lorem-ipsum.txt.sha256.asc.bad")
        }
        Assertions.assertTrue(ex.message!!.startsWith("Signature verification failed for"))
    }

    @Test
    fun wrongFormat() {
        val ex = assertThrows<IllegalStateException> {
            runTest(
                detachedSignatureFileName = "lorem-ipsum.txt.badformat.sha256.asc",
                checksumFile = "lorem-ipsum.txt.badformat.sha256",
            )
        }
        Assertions.assertTrue(ex.message!!.startsWith("Checksum file does not match regex"), ex.message!!)
    }

    @Test
    fun badSignature() {
        val ex = assertThrows<IllegalStateException> {
            runTest(detachedSignatureFileName = "lorem-ipsum.txt.sha256.asc.bad")
        }
        Assertions.assertTrue(ex.message!!.startsWith("Signature verification failed for"))
    }

    @Test
    fun everythingOk() {
        runTest(detachedSignatureFileName = "lorem-ipsum.txt.sha256.asc")
    }

    private fun runTest(detachedSignatureFileName: String, checksumFile: String? = null) {
        Sha256ChecksumSignatureVerifier.verifyChecksumAndSignature(
            file = TestUtil.getTestDataFile("lorem-ipsum.txt"),
            detachedSignatureFile = TestUtil.getTestDataFile(detachedSignatureFileName),
            checksumFile = TestUtil.getTestDataFile(checksumFile ?: "lorem-ipsum.txt.sha256"),
            expectedFileName = "lorem-ipsum.txt",
            untrustedPublicKeyRing = ByteArrayInputStream(TestUtil.getTestDataBytes(PgpSignatureVerifierTest.RealPublicKeys)),
            trustedMasterKey = ByteArrayInputStream(JetBrainsPgpConstants.JETBRAINS_DOWNLOADS_PGP_MASTER_PUBLIC_KEY.toByteArray()),
        )
    }
}