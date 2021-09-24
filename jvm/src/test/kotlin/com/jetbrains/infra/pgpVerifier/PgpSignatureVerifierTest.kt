package com.jetbrains.infra.pgpVerifier

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URL
import java.nio.file.Files
import java.util.stream.Stream


class PgpSignatureVerifierTest {
    @ParameterizedTest
    @MethodSource("verifyTestCases")
    fun verify(masterPublicKeyResourceName: String, publicKeysResourceName: String, signatureResourceName: String, dataResourceName: String, expectedResult: Boolean) {
        val masterPublicKey = TestUtil.getTestDataFile(masterPublicKeyResourceName)
        val publicKeys = TestUtil.getTestDataFile(publicKeysResourceName)
        val signature = TestUtil.getTestDataFile(signatureResourceName)
        val data = TestUtil.getTestDataFile(dataResourceName)

        Files.newInputStream(signature).use { signatureStream ->
            Files.newInputStream(publicKeys).use { publicKeysStream ->
                Files.newInputStream(masterPublicKey).use { masterPublicKeyStream ->
                    // masterPublicKey contains a public key + user id + signatures. extract master key only
                    val masterPublicKeyOnlyBytes = BCPGInputStream(ArmoredInputStream(masterPublicKeyStream)).use {
                        it.readPacket() as PublicKeyPacket
                    }.encoded

                    val masterPublicKeyOnlyArmoredBytes = ByteArrayOutputStream().also {
                        ArmoredOutputStream(it).use { armored -> armored.write(masterPublicKeyOnlyBytes) }
                    }.toByteArray()

                    val result = try {
                        PgpSignaturesVerifier.verifySignature(
                            file = data,
                            detachedSignatureInputStream = signatureStream,
                            untrustedPublicKeyBundleInputStream = publicKeysStream,
                            trustedMasterKeyInputStream = ByteArrayInputStream(masterPublicKeyOnlyArmoredBytes),
                            logger = TestPgpSignaturesVerifierLogger,
                        )
                        true
                    } catch (_: Throwable) {
                        false
                    }

                    Assertions.assertEquals(expectedResult, result)
                }
            }
        }
    }

    @ParameterizedTest
    @MethodSource("downloadVerifyTestCases")
    fun downloadVerify(signatureResourceName: String, dataResourceName: String, expectedResult: Boolean) {
        val signature = TestUtil.getTestDataFile(signatureResourceName)
        val data = TestUtil.getTestDataFile(dataResourceName)

        Files.newInputStream(signature).use { signatureStream ->
            ByteArrayInputStream(realSubKeys).use { publicKeysStream ->
                ByteArrayInputStream(JetBrainsPgpConstants.JETBRAINS_DOWNLOADS_PGP_MASTER_PUBLIC_KEY.toByteArray()).use { masterPublicKeyStream ->
                    val result = try {
                        PgpSignaturesVerifier.verifySignature(
                            file = data,
                            detachedSignatureInputStream = signatureStream,
                            untrustedPublicKeyBundleInputStream = publicKeysStream,
                            trustedMasterKeyInputStream = masterPublicKeyStream,
                            logger = TestPgpSignaturesVerifierLogger,
                        )
                        true
                    } catch (_: Throwable) {
                        false
                    }

                    Assertions.assertEquals(expectedResult, result)
                }
            }
        }
    }

    @Test
    fun equalMasterPublicKeyTest() {
        val trustedMasterKeyText = Files.readString(TestUtil.getTestDataFile(RealMasterPublicKey))
        val trustedMasterKeyRingCollection = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(ByteArrayInputStream(trustedMasterKeyText.toByteArray())),
            JcaKeyFingerprintCalculator()
        )
        val trustedMasterKeyRing = trustedMasterKeyRingCollection.singleOrNull()
            ?: error("Only one key ring should be in trustedMasterKeyInputStream")
        val trustedMasterKey2 = trustedMasterKeyRing.publicKeys.asSequence().toList().singleOrNull()
            ?: error("Only one key should be in trustedMasterKeyRing")

        val os = ByteArrayOutputStream()
        ArmoredOutputStream(os).use { it.write(trustedMasterKey2.publicKeyPacket.encoded) }
        val trustedMasterPublicKeyText = os.toByteArray().decodeToString()

        Assertions.assertEquals(
            JetBrainsPgpConstants.JETBRAINS_DOWNLOADS_PGP_MASTER_PUBLIC_KEY.replace("\r", "").trim(),
            trustedMasterPublicKeyText.replace("\r", "").trim()
        )
    }

    companion object {
        val realSubKeys: ByteArray by lazy {
            URL(JetBrainsPgpConstants.JETBRAINS_DOWNLOADS_PGP_SUB_KEYS_URL).openStream().use { it.readAllBytes() }
        }

        private const val RealMasterPublicKey = "real-master-public-key.asc"
        private const val TestMasterPublicKey = "test-master-public-key.asc"
        private const val FailMasterPublicKey = "fail-master-public-key.asc"

        const val RealPublicKeys = "real-public-keys.asc"
        private const val TestNoRevokePublicKeys = "test-no-revoke-public-keys.asc"
        private const val TestTwoRevokePublicKeys = "test-two-revoke-public-keys.asc"

        private const val FailData = "fail-data.bin"
        private const val RealData0 = "real-data.0.bin"
        private const val RealData1 = "real-data.1.bin"
        private const val TestData0 = "test-data.0.bin"
        private const val TestData1 = "test-data.1.bin"
        private const val TestData2 = "test-data.2.bin"
        private const val TestData3 = "test-data.3.bin"

        private const val RealSignature0Asc = "real-signature.0.asc"
        private const val RealSignature1Asc = "real-signature.1.asc"
        private const val RealSignature0Gpg = "real-signature.0.gpg"
        private const val RealSignature1Gpg = "real-signature.1.gpg"
        private const val TestSignature0Asc = "test-signature.0.asc"
        private const val TestSignature1Asc = "test-signature.1.asc"
        private const val TestSignature2Asc = "test-signature.2.asc"
        private const val TestSignature3Asc = "test-signature.3.asc"
        private const val TestSignature0Gpg = "test-signature.0.gpg"
        private const val TestSignature1Gpg = "test-signature.1.gpg"
        private const val TestSignature2Gpg = "test-signature.2.gpg"
        private const val TestSignature3Gpg = "test-signature.3.gpg"

        @JvmStatic
        fun verifyTestCases(): Stream<Arguments> = Stream.of(
            Arguments.of(RealMasterPublicKey, RealPublicKeys, RealSignature0Asc, RealData0, true),
            Arguments.of(RealMasterPublicKey, RealPublicKeys, RealSignature1Asc, RealData1, true),
            Arguments.of(RealMasterPublicKey, RealPublicKeys, RealSignature0Gpg, RealData0, true),
            Arguments.of(RealMasterPublicKey, RealPublicKeys, RealSignature1Gpg, RealData1, true),
            Arguments.of(RealMasterPublicKey, RealPublicKeys, RealSignature0Asc, FailData, false),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Asc, TestData0, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature1Asc, TestData1, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature2Asc, TestData2, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature3Asc, TestData3, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Gpg, TestData0, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature1Gpg, TestData1, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature2Gpg, TestData2, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature3Gpg, TestData3, true),
            Arguments.of(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Asc, FailData, false),
            Arguments.of(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature0Asc, TestData0, true),
            Arguments.of(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature1Asc, TestData1, true),
            Arguments.of(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature2Asc, TestData2, true),
            Arguments.of(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature3Asc, TestData3, false),
            Arguments.of(FailMasterPublicKey, RealPublicKeys, RealSignature0Asc, RealData0, false),
            Arguments.of(FailMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Asc, TestData0, false),
        )

        @JvmStatic
        fun downloadVerifyTestCases(): Stream<Arguments> = Stream.of(
            Arguments.of(RealSignature0Asc, RealData0, true),
            Arguments.of(RealSignature1Asc, RealData1, true),
            Arguments.of(RealSignature0Gpg, RealData0, true),
            Arguments.of(RealSignature1Gpg, RealData1, true),
            Arguments.of(RealSignature0Asc, FailData, false),
        )
    }
}