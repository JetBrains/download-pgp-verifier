using System;
using System.IO;
using System.Linq;
using JetBrains.Annotations;
using NUnit.Framework;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace JetBrains.DownloadVerifier.Tests
{
  public class KeysUtilTests
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
      var type = typeof(KeysUtilTests);
      return type.Assembly.OpenStreamFromResource(type.Namespace + ".Resources." + resourceName, handler);
    }

    [TestCase(RealMasterPublicKey)]
    [TestCase(TestMasterPublicKey)]
    [TestCase(FailMasterPublicKey)]
    public void MasterPublicKeyTest(string masterPublicKeyResourceName)
    {
      var masterPublicKey = StreamFromResource(masterPublicKeyResourceName, KeysUtil.GetTrustedMasterPublicKey);
      Console.WriteLine("KeyID: {0:X16}", masterPublicKey.KeyId);
      Console.WriteLine("BitStrength: {0}", masterPublicKey.BitStrength);
      Console.WriteLine("CreationTime: {0:s}", masterPublicKey.CreationTime);
      Console.WriteLine("Valid: {0:g}", TimeSpan.FromSeconds(masterPublicKey.GetValidSeconds()));

      Assert.AreEqual(4, masterPublicKey.Version);
      Assert.LessOrEqual(2048, masterPublicKey.BitStrength);
      Assert.AreEqual(PublicKeyAlgorithmTag.RsaGeneral, masterPublicKey.Algorithm);
      Assert.IsTrue(masterPublicKey.IsMasterKey);
      Assert.IsFalse(masterPublicKey.IsRevoked());

      var verified = 0;
      foreach (string uid in masterPublicKey.GetUserIds())
      foreach (PgpSignature sign in masterPublicKey.GetSignaturesForId(uid))
        if (sign.IsCertification())
          if (sign.KeyId == masterPublicKey.KeyId)
          {
            sign.InitVerify(masterPublicKey);
            Assert.IsTrue(sign.VerifyCertification(uid, masterPublicKey));
            ++verified;
          }

      Assert.LessOrEqual(1, verified);
    }

    [TestCase(RealMasterPublicKey, RealPublicKeys, 0)]
    [TestCase(TestMasterPublicKey, TestNoRevokePublicKeys, 0)]
    [TestCase(TestMasterPublicKey, TestTwoRevokePublicKeys, 2)]
    public void PublicKeyRingsTest(string masterPublicKeyResourceName, string publicKeysResourceName, int expectedRevoked)
    {
      var masterPublicKey = StreamFromResource(masterPublicKeyResourceName, KeysUtil.GetTrustedMasterPublicKey);
      Console.WriteLine("MasterKeyID: {0:X16}", masterPublicKey.KeyId);
      Console.WriteLine("MasterBitStrength: {0}", masterPublicKey.BitStrength);
      Console.WriteLine("MasterCreationTime: {0:s}", masterPublicKey.CreationTime);
      Console.WriteLine("MasterValid: {0:g}", TimeSpan.FromSeconds(masterPublicKey.GetValidSeconds()));
      var revoked = 0;
      var n = 0;
      foreach (PgpPublicKeyRing ring in StreamFromResource(publicKeysResourceName, KeysUtil.GetUntrustedPublicKeyRingBundle).GetKeyRings())
      {
        Console.WriteLine("#{0}", n++);
        var k = 0;
        foreach (PgpPublicKey publicKey in ring.GetPublicKeys())
          if (!publicKey.IsMasterKey)
          {
            Console.WriteLine(" #{0}", k++);
            Console.WriteLine("    KeyID: {0:X16}", publicKey.KeyId);
            Console.WriteLine("    BitStrength: {0}", publicKey.BitStrength);
            Console.WriteLine("    CreationTime: {0:s}", publicKey.CreationTime);
            Console.WriteLine("    Valid: {0:g}", TimeSpan.FromSeconds(publicKey.GetValidSeconds()));
            Console.WriteLine("    IsRevoked: {0}", publicKey.IsRevoked());

            Assert.AreEqual(4, publicKey.Version);
            Assert.LessOrEqual(2048, publicKey.BitStrength);
            Assert.AreEqual(PublicKeyAlgorithmTag.RsaGeneral, publicKey.Algorithm);
            if (publicKey.IsRevoked())
              ++revoked;

            var succeeded = 0;
            var failed = 0;
            foreach (PgpSignature sign in publicKey.GetKeySignatures())
            {
              if (sign.SignatureType != PgpSignature.SubkeyBinding) continue;
              sign.InitVerify(masterPublicKey);
              if (sign.VerifyCertification(masterPublicKey, publicKey))
                ++succeeded;
              else
                ++failed;
            }

            Assert.AreEqual(0, failed);
            Assert.Less(0, succeeded);
          }
      }

      Assert.AreEqual(expectedRevoked, revoked);
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
      var masterPublicKey = StreamFromResource(masterPublicKeyResourceName, KeysUtil.GetTrustedMasterPublicKey);
      var publicKeyRingBundle = StreamFromResource(publicKeysResourceName, KeysUtil.GetUntrustedPublicKeyRingBundle);
      var signatures = StreamFromResource(signatureResourceName, KeysUtil.GetSignatures);
      var result = StreamFromResource(dataResourceName, stream => KeysUtil.Verify(masterPublicKey, publicKeyRingBundle, signatures, stream, ConsoleLogger.Instance));
      Assert.AreEqual(expectedResult, result);
    }

    [Test]
    public void MasterPublicKeyTest()
    {
      var masterPublicKey0 = Constants.MasterPublicKey;
      var masterPublicKey1 = StreamFromResource(RealMasterPublicKey, KeysUtil.GetTrustedMasterPublicKey);
      Assert.AreEqual(masterPublicKey0.KeyId, masterPublicKey1.KeyId);
      Assert.IsTrue(masterPublicKey0.GetFingerprint().SequenceEqual(masterPublicKey1.GetFingerprint()));
    }

    [Test]
    public void DownloadKeysTest()
    {
      foreach (PgpPublicKeyRing ring in Constants.PublicKeysUri.OpenStreamFromWeb(KeysUtil.GetUntrustedPublicKeyRingBundle).GetKeyRings())
      foreach (PgpPublicKey publicKey in ring.GetPublicKeys())
      {
      }
    }

    private sealed class ConsoleLogger : ILogger
    {
      public static readonly ILogger Instance = new ConsoleLogger();

      private ConsoleLogger()
      {
      }

      void ILogger.Info(string str)
      {
        Console.WriteLine(str);
      }

      void ILogger.Warning(string str)
      {
        Console.Error.WriteLine("WARNING: " + str);
      }

      void ILogger.Error(string str)
      {
        Console.Error.WriteLine("ERROR: " + str);
      }
    }
  }
}