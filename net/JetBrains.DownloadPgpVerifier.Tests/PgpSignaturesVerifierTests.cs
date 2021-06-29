using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using JetBrains.Annotations;
using NUnit.Framework;

namespace JetBrains.DownloadPgpVerifier.Tests
{
  [SuppressMessage("ReSharper", "InconsistentNaming")]
  public class PgpSignaturesVerifierTests
  {
    private const string RealMasterPublicKey = "real-master-public-key.asc";
    private const string TestMasterPublicKey = "test-master-public-key.asc";
    private const string FailMasterPublicKey = "fail-master-public-key.asc";

    private const string RealPublicKeys = "real-public-keys.asc";
    private const string TestNoRevokePublicKeys = "test-no-revoke-public-keys.asc";
    private const string TestTwoRevokePublicKeys = "test-two-revoke-public-keys.asc";

    private const string FailData = "fail-data.bin";
    private const string RealData0 = "real-data.0.bin";
    private const string RealData1 = "real-data.1.bin";
    private const string TestData0 = "test-data.0.bin";
    private const string TestData1 = "test-data.1.bin";
    private const string TestData2 = "test-data.2.bin";
    private const string TestData3 = "test-data.3.bin";

    private const string RealSignature0Asc = "real-signature.0.asc";
    private const string RealSignature1Asc = "real-signature.1.asc";
    private const string RealSignature0Gpg = "real-signature.0.gpg";
    private const string RealSignature1Gpg = "real-signature.1.gpg";
    private const string TestSignature0Asc = "test-signature.0.asc";
    private const string TestSignature1Asc = "test-signature.1.asc";
    private const string TestSignature2Asc = "test-signature.2.asc";
    private const string TestSignature3Asc = "test-signature.3.asc";
    private const string TestSignature0Gpg = "test-signature.0.gpg";
    private const string TestSignature1Gpg = "test-signature.1.gpg";
    private const string TestSignature2Gpg = "test-signature.2.gpg";
    private const string TestSignature3Gpg = "test-signature.3.gpg";

    private static TResult StreamFromResource<TResult>([NotNull] string resourceName, [NotNull] Func<Stream, TResult> handler)
    {
      var type = typeof(PgpSignaturesVerifierTests);
      return type.Assembly.OpenStreamFromResource(type.Namespace + ".Resources." + resourceName, handler);
    }

    [TestCase(RealMasterPublicKey, RealPublicKeys, RealSignature0Asc, RealData0, true)]
    [TestCase(RealMasterPublicKey, RealPublicKeys, RealSignature1Asc, RealData1, true)]
    [TestCase(RealMasterPublicKey, RealPublicKeys, RealSignature0Gpg, RealData0, true)]
    [TestCase(RealMasterPublicKey, RealPublicKeys, RealSignature1Gpg, RealData1, true)]
    [TestCase(RealMasterPublicKey, RealPublicKeys, RealSignature0Asc, FailData, false)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Asc, TestData0, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature1Asc, TestData1, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature2Asc, TestData2, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature3Asc, TestData3, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Gpg, TestData0, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature1Gpg, TestData1, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature2Gpg, TestData2, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature3Gpg, TestData3, true)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Asc, FailData, false)]
    [TestCase(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature0Asc, TestData0, true)]
    [TestCase(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature1Asc, TestData1, true)]
    [TestCase(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature2Asc, TestData2, true)]
    [TestCase(TestMasterPublicKey, TestTwoRevokePublicKeys, TestSignature3Asc, TestData3, false)]
    [TestCase(FailMasterPublicKey, RealPublicKeys, RealSignature0Asc, RealData0, false)]
    [TestCase(FailMasterPublicKey, TestNoRevokePublicKeys, TestSignature0Asc, TestData0, false)]
    public void VerifyTest(string masterPublicKeyResourceName, string publicKeysResourceName, string signatureResourceName, string dataResourceName, bool expectedResult)
    {
      var result = StreamFromResource(masterPublicKeyResourceName,
        masterPublicKeyStream => StreamFromResource(publicKeysResourceName,
          publicKeysStream => StreamFromResource(signatureResourceName,
            signaturesStream => StreamFromResource(dataResourceName,
              dataStream => PgpSignaturesVerifier.Verify(masterPublicKeyStream, publicKeysStream, signaturesStream, dataStream, ConsoleLogger.Instance)))));
      Assert.AreEqual(expectedResult, result);
    }

    [Test]
    public void EqualMasterPublicKeyTest()
    {
      Assert.AreEqual(PgpSignaturesVerifier.MasterPublicKey, StreamFromResource(RealMasterPublicKey, stream =>
        {
          using var reader = new StreamReader(stream, Encoding.ASCII);
          return reader.ReadToEnd();
        }));
    }

    [TestCase(RealSignature0Asc, RealData0, true)]
    [TestCase(RealSignature1Asc, RealData1, true)]
    [TestCase(RealSignature0Gpg, RealData0, true)]
    [TestCase(RealSignature1Gpg, RealData1, true)]
    [TestCase(RealSignature0Asc, FailData, false)]
    public void DownloadVerifyTest(string signatureResourceName, string dataResourceName, bool expectedResult)
    {
      var result = PgpSignaturesVerifier.MasterPublicKey.OpenStreamFromString(
        masterPublicKeyStream => PgpSignaturesVerifier.PublicKeysUri.OpenSeekableStreamFromWeb(
          publicKeysStream => StreamFromResource(signatureResourceName,
            signaturesStream => StreamFromResource(dataResourceName,
              dataStream => PgpSignaturesVerifier.Verify(masterPublicKeyStream, publicKeysStream, signaturesStream, dataStream, ConsoleLogger.Instance)))));
      Assert.AreEqual(expectedResult, result);
    }
  }
}